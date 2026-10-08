package amqpconfirm

import (
	"context"
	"errors"
	"strings"
	"testing"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

func TestAwaitRejectsReturnEvenWhenAckReady(t *testing.T) {
	for range 100 {
		confirms := make(chan amqp091.Confirmation, 1)
		returns := make(chan amqp091.Return, 1)
		returns <- amqp091.Return{ReplyCode: 312, ReplyText: "NO_ROUTE"}
		confirms <- amqp091.Confirmation{Ack: true}
		if err := Await(context.Background(), "test", confirms, returns); err == nil || !strings.Contains(err.Error(), "NO_ROUTE") {
			t.Fatalf("unroutable publish accepted: %v", err)
		}
	}
}

func TestAwaitConfirmationFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		ack, closed bool
	}{
		{name: "ack", ack: true}, {name: "nack"}, {name: "closed", closed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			confirms := make(chan amqp091.Confirmation, 1)
			returns := make(chan amqp091.Return, 1)
			close(returns)
			if test.closed {
				close(confirms)
			} else {
				confirms <- amqp091.Confirmation{Ack: test.ack}
			}
			if err := Await(context.Background(), "test", confirms, returns); (err == nil) != test.ack {
				t.Fatalf("unexpected receipt outcome: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Await(ctx, "test", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not propagated: %v", err)
	}
}
