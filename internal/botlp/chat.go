// Chat bridges: mapping concrete whitelisted platforms onto the generic
// send/poll contract. A chat platform exposes one global message stream
// (a conversation the operator's bot is a member of) instead of
// per-room mailboxes, so the bridge multiplexes rooms inside message
// texts and maintains per-room cursors over the shared stream:
//
//	message text:  qulogi|<room>|<base64 frame>
//
// Direction disambiguation is inherited from the mailbox model: the
// client writes the session room and reads <room>-r, the relay does the
// opposite — a side never consumes frames tagged with the room it
// writes, so no self-echo happens even though both sides poll the same
// conversation. Control announcements ("open:<room>") ride the same
// tagging and unwrap in front of parseOpen on the relay.
package botlp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// chatTag prefixes every bridged message.
const chatTag = "qulogi"

// chatFrameLimit bounds the raw frame size for chat platforms whose
// message length caps around 4096 characters (VK): the encoded text is
// tag + room + base64(frame), so the raw payload stays well below it.
const chatFrameLimit = 2800

// ChatAPI is the platform face a concrete bridge implements: send one
// text into the operator conversation and long-poll new texts. The
// cursor is opaque and monotonic (VK long-poll ts, Max updates marker).
type ChatAPI interface {
	SendText(ctx context.Context, text string) error
	PollTexts(ctx context.Context, wait time.Duration) (cursor uint64, texts []string, err error)
}

// ChatBridge adapts a ChatAPI to the API contract. Create one per side
// (client and relay keep independent cursors).
type ChatBridge struct {
	Chat ChatAPI
	// Wait is the long-poll window (default 25s, clamped 1..60s).
	Wait time.Duration
	// Log receives bridge events (optional).
	Log func(string)

	// pollMu serialises global-stream consumption: exactly one
	// PollTexts round may run at a time, otherwise two room polls race
	// the shared cursor and miss frames.
	pollMu sync.Mutex
	mu     sync.Mutex
	cursor uint64
	curSet bool
	rooms  map[string]*chatRoom
}

type chatRoom struct {
	seq  uint64
	pend [][]byte
}

// NewChatBridge wraps a platform chat stream.
func NewChatBridge(chat ChatAPI) *ChatBridge {
	return &ChatBridge{Chat: chat, Wait: defaultPollWait * time.Second, rooms: map[string]*chatRoom{}}
}

func encodeFrame(room string, data []byte) string {
	return chatTag + "|" + room + "|" + base64.StdEncoding.EncodeToString(data)
}

// decodeFrame splits a bridged message; ok=false for foreign texts.
func decodeFrame(text string) (room string, data []byte, ok bool) {
	parts := strings.Split(text, "|")
	if len(parts) != 3 || parts[0] != chatTag || parts[1] == "" {
		return "", nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, false
	}
	return parts[1], raw, true
}

// Send posts one frame to the room as a tagged message.
func (b *ChatBridge) Send(ctx context.Context, room string, data []byte) error {
	if err := validRoom(room); err != nil {
		return err
	}
	b.logf("send -> %s (%dB)", room, len(data))
	return b.Chat.SendText(ctx, encodeFrame(room, data))
}

func (b *ChatBridge) logf(format string, args ...any) {
	if b.Log != nil {
		b.Log(fmt.Sprintf("chat: "+format, args...))
	}
}

func totalLen(frames [][]byte) int {
	n := 0
	for _, f := range frames {
		n += len(f)
	}
	return n
}

// Poll drains the global stream until frames for the room show up (or
// the platform window elapses without traffic — an empty result mirrors
// the generic long-poll timeout contract).
func (b *ChatBridge) Poll(ctx context.Context, room string, seq uint64) (uint64, [][]byte, error) {
	if err := validRoom(room); err != nil {
		return seq, nil, err
	}
	b.mu.Lock()
	st := b.rooms[room]
	if st == nil {
		st = &chatRoom{}
		b.rooms[room] = st
	}
	b.mu.Unlock()

	wait := b.Wait
	if wait <= 0 {
		wait = defaultPollWait * time.Second
	}
	wait = clampDur(wait, time.Second, time.Minute)

	for {
		// Deliver buffered frames for this room (under the state lock).
		b.mu.Lock()
		if len(st.pend) > 0 {
			frames := st.pend
			st.pend = nil
			st.seq += uint64(len(frames))
			b.mu.Unlock()
			b.logf("poll(%s) deliver %d frames (%dB)", room, len(frames), totalLen(frames))
			return st.seq, frames, nil
		}
		b.mu.Unlock()

		if err := ctx.Err(); err != nil {
			return seq, nil, err
		}
		// One global-stream round; pollMu serialises consumption so
		// concurrent room polls cannot race the shared cursor. A round
		// parks in the platform long-poll, so waiters never block on the
		// mutex: they spin on their own queue — the round in flight
		// delivers frames to every room, including theirs.
		if !b.pollMu.TryLock() {
			select {
			case <-ctx.Done():
				return seq, nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		cursor, texts, err := b.Chat.PollTexts(ctx, wait)
		b.pollMu.Unlock()
		if err != nil {
			return seq, nil, err
		}
		b.logf("poll(%s) round cursor=%d texts=%d", room, cursor, len(texts))
		b.mu.Lock()
		if !b.curSet || cursor > b.cursor {
			b.cursor = cursor
			b.curSet = true
		}
		b.mu.Unlock()
		for _, text := range texts {
			r, data, ok := decodeFrame(strings.TrimSpace(text))
			if !ok {
				continue
			}
			b.mu.Lock()
			roomState := b.rooms[r]
			if roomState == nil {
				roomState = &chatRoom{}
				b.rooms[r] = roomState
			}
			// Rooms nobody polls (e.g. our own writes mirrored back on a
			// shared stream) must not grow without bound.
			if len(roomState.pend) < 256 {
				roomState.pend = append(roomState.pend, data)
			}
			b.mu.Unlock()
		}
	}
}

// validRoom guards the room name: it travels inside message texts.
func validRoom(room string) error {
	if room == "" || len(room) > 64 || strings.ContainsAny(room, "|\r\n") {
		return fmt.Errorf("botlp: bad room %q", room)
	}
	return nil
}

// BuildAPI constructs the platform adapter named by kind: "" is the
// generic send/poll contract, "vk" and "max" are the chat bridges.
// It returns the adapter together with the frame chunk the pipe should
// use (0 keeps the pipe default).
func BuildAPI(kind, url, token, room, chat string) (API, int, error) {
	switch kind {
	case "", "generic":
		if url == "" {
			return nil, 0, errors.New("botlp: platform base url required")
		}
		p, err := NewPlatform(url, token)
		if err != nil {
			return nil, 0, err
		}
		if room == "" {
			return nil, 0, errors.New("botlp: base room required")
		}
		return p, 0, nil
	case "vk":
		b, err := NewVKChat(url, token, chat)
		if err != nil {
			return nil, 0, err
		}
		return NewChatBridge(b), chatFrameLimit, nil
	case "max":
		b, err := NewMaxChat(url, token, chat)
		if err != nil {
			return nil, 0, err
		}
		return NewChatBridge(b), chatFrameLimit, nil
	default:
		return nil, 0, fmt.Errorf("botlp: unknown platform kind %q (want generic, vk or max)", kind)
	}
}

// chatID parses a decimal peer/chat id.
func chatID(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("botlp: bad chat id %q", raw)
	}
	return id, nil
}
