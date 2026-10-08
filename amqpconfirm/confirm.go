// Package amqpconfirm verifies mandatory AMQP publisher receipts.
package amqpconfirm

import (
	"context"
	"fmt"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

// Await succeeds only for a positive confirmation without a returned message.
// Use a dedicated channel with one outstanding mandatory publish; listeners
// must be registered before publishing and buffered to hold its return/confirm.
// AMQP delivers a mandatory return before the confirmation, so the ACK branch
// also drains an already-buffered return before declaring success.
func Await(ctx context.Context, action string, confirms <-chan amqp091.Confirmation, returns <-chan amqp091.Return) error {
	for {
		select {
		case returned, ok := <-returns:
			if !ok {
				returns = nil
				continue
			}
			return fmt.Errorf("%s was returned by broker: %d %s", action, returned.ReplyCode, returned.ReplyText)
		case confirmed, ok := <-confirms:
			if !ok {
				return fmt.Errorf("%s confirm channel closed", action)
			}
			if !confirmed.Ack {
				return fmt.Errorf("%s was nacked by broker", action)
			}
			select {
			case returned, ok := <-returns:
				if ok {
					return fmt.Errorf("%s was returned by broker: %d %s", action, returned.ReplyCode, returned.ReplyText)
				}
			default:
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
