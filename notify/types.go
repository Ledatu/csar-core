// Package notify provides producer-facing notification transport helpers.
package notify

// Channel identifies a delivery channel a producer can request explicitly.
type Channel string

const (
	ChannelUnspecified Channel = ""
	ChannelSite        Channel = "site"
	ChannelTelegram    Channel = "telegram"
	ChannelEmail       Channel = "email"
)

// Priority controls delivery urgency from the producer's perspective.
type Priority string

const (
	PriorityUnspecified Priority = ""
	PriorityLow         Priority = "low"
	PriorityNormal      Priority = "normal"
	PriorityHigh        Priority = "high"
	PriorityUrgent      Priority = "urgent"
)

// Notification is the producer-facing ingest payload.
type Notification struct {
	ID         string            `json:"id,omitempty"`
	Topic      string            `json:"topic"`
	Title      string            `json:"title"`
	Body       string            `json:"body,omitempty"`
	Link       string            `json:"link,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Priority   Priority          `json:"priority,omitempty"`
	Recipients []string          `json:"recipients,omitempty"`
	Channels   []Channel         `json:"channels,omitempty"`
	Sender     string            `json:"sender,omitempty"`
}

func cloneNotification(n *Notification) *Notification {
	if n == nil {
		return nil
	}

	cp := *n
	if len(n.Metadata) > 0 {
		cp.Metadata = make(map[string]string, len(n.Metadata))
		for k, v := range n.Metadata {
			cp.Metadata[k] = v
		}
	}
	if len(n.Recipients) > 0 {
		cp.Recipients = append([]string(nil), n.Recipients...)
	}
	if len(n.Channels) > 0 {
		cp.Channels = append([]Channel(nil), n.Channels...)
	}

	return &cp
}
