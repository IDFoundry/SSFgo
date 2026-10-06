// Package ssftest runs an SSF Transmitter or Receiver in-process, for
// testing an application that plays the other role.
//
// To test a Receiver, start a Transmitter and build the Receiver from the
// configuration it suggests:
//
//	tx := ssftest.NewTransmitter(t)
//	rx, err := receiver.New(ctx, tx.ReceiverConfig(registry))
//	stream, err := rx.EnsureStream(ctx, receiver.StreamRequest{})
//	err = tx.Emit(ctx, subject, event)
//	_, err = rx.Poll(ctx, stream, receiver.PollOptions{})
//
// To test a Transmitter, start a Receiver's push endpoint, build the
// Transmitter to push with its client, connect the Receiver, and point a
// stream at the endpoint:
//
//	rx := ssftest.NewReceiver(t)
//	tx := newTransmitterUnderTest(rx.PushClient())
//	rx.Connect(receiver.Config{Issuer: ..., Audience: ..., TokenSource: ..., HTTPClient: ...})
//	_, err := rx.Receiver().CreateStream(ctx, rx.PushStreamRequest())
//	// make the Transmitter emit, then
//	sets := rx.WaitFor(1)
//
// Both are real SSFgo implementations on TLS test servers, closed when the
// test ends. They are for tests only: certificates, keys and credentials
// are generated per test and checked by nothing but each other.
package ssftest
