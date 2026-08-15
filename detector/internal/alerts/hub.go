package alerts

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/sahraali252/sentinel/detector/internal/model"
)

type Hub struct {
	mu      sync.Mutex
	clients map[chan model.Alert]struct{}
	logger  *slog.Logger
}

func NewHub(logger *slog.Logger) *Hub {
	return &Hub{clients: make(map[chan model.Alert]struct{}), logger: logger}
}

func (h *Hub) Publish(alert model.Alert) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for client := range h.clients {
		select {
		case client <- alert:
		default:
			close(client)
			delete(h.clients, client)
			h.logger.Warn("slow WebSocket client disconnected")
		}
	}
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"localhost:*", "127.0.0.1:*"}})
	if err != nil {
		h.logger.Warn("WebSocket upgrade rejected", "error", err)
		return
	}
	defer connection.CloseNow()
	client := make(chan model.Alert, 64)
	h.mu.Lock()
	h.clients[client] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if _, exists := h.clients[client]; exists {
			delete(h.clients, client)
			close(client)
		}
		h.mu.Unlock()
	}()
	for alert := range client {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		err := wsjson.Write(ctx, connection, alert)
		cancel()
		if err != nil {
			return
		}
	}
}
