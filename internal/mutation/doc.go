// Package mutation runs untrusted slice mutation scripts against a committed
// virtual filesystem inside a resource- and capability-bounded worker process.
//
// Nothing here is exposed to users yet: the evaluator is a directive stand-in
// until the restricted content API replaces it.
package mutation
