package event

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/skoczo/repgate/internal/model"
)

type EventRepository interface {
	Insert(ctx context.Context, e *model.Event) error
	GetEvents(ctx context.Context, beforeID int64, limit int, action string) ([]model.Event, error)
}

type Service struct {
	eventRepo     EventRepository
	eventChan     chan model.Event
	subscribers   map[chan model.Event]struct{}
	subMu         sync.Mutex
	retentionDays int
}

func NewService(eventRepo EventRepository, retentionDays int) *Service {
	s := &Service{
		eventRepo:     eventRepo,
		eventChan:     make(chan model.Event, 10000),
		subscribers:   make(map[chan model.Event]struct{}),
		retentionDays: retentionDays,
	}

	go s.startEventProcessor()

	return s
}

func (s *Service) Subscribe() chan model.Event {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	ch := make(chan model.Event, 100)
	s.subscribers[ch] = struct{}{}
	return ch
}

func (s *Service) Unsubscribe(ch chan model.Event) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	delete(s.subscribers, ch)
	close(ch)
}

func (s *Service) Publish(ip, targetHost, targetPath, action, source string) {
	if s.retentionDays == 0 {
		return
	}

	if source == "" {
		source = "System"
	}
	event := model.Event{
		IP:         ip,
		TargetHost: targetHost,
		TargetPath: targetPath,
		Action:     action,
		Source:     source,
		Timestamp:  time.Now(),
	}
	select {
	case s.eventChan <- event:
	default:
		slog.Warn("event channel full, event dropped", "ip", ip, "action", action)
	}
}

func (s *Service) GetEvents(ctx context.Context, beforeID int64, limit int, action string) ([]model.Event, error) {
	if s.eventRepo == nil {
		return []model.Event{}, nil
	}
	return s.eventRepo.GetEvents(ctx, beforeID, limit, action)
}

func (s *Service) RetentionDays() int {
	return s.retentionDays
}

func (s *Service) startEventProcessor() {
	for e := range s.eventChan {
		if s.eventRepo != nil {
			dbCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := s.eventRepo.Insert(dbCtx, &e)
			cancel()
			if err != nil {
				slog.Error("failed to save event to database", "error", err)
			}
		}

		s.subMu.Lock()
		for ch := range s.subscribers {
			select {
			case ch <- e:
			default:
			}
		}
		s.subMu.Unlock()
	}
}
