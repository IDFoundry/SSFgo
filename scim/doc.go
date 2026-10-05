// Package scim implements the SCIM events of RFC 9967 on top of the Shared
// Signals Framework: provisioning changes of a SCIM service provider —
// resources created, patched, replaced, deleted, activated and deactivated
// — feed membership changes, and the completion of asynchronous SCIM
// requests.
//
// Call Register to add them to an ssf.Registry:
//
//	r := ssf.NewRegistry()
//	if err := scim.Register(r); err != nil { ... }
//
// Every SCIM event's subject is an ssf.SCIMSubject (RFC 9967 §2.1). The
// provisioning events come in two modes, each its own type: "full" carries
// the resource, or the SCIM PATCH request, in Data; "notice" names the
// attributes that changed, which the Receiver may fetch with a SCIM GET of
// the subject's URI.
//
// RFC 9967 lets one SET carry several events of the same transaction.
// SSFgo's SETs carry exactly one event, so a Transmitter emits each event
// in its own SET under a shared "txn" — with transmitter.EmitTxn — and a
// Receiver rejects a SET with several events as invalid_request.
package scim
