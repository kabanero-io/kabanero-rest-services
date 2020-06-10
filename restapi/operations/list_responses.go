// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/davco01a/kabanero-rest-services/models"
)

// ListCreatedCode is the HTTP code returned for type ListCreated
const ListCreatedCode int = 201

/*ListCreated login successful

swagger:response listCreated
*/
type ListCreated struct {

	/*
	  In: Body
	*/
	Payload *models.StacksList `json:"body,omitempty"`
}

// NewListCreated creates ListCreated with default headers values
func NewListCreated() *ListCreated {

	return &ListCreated{}
}

// WithPayload adds the payload to the list created response
func (o *ListCreated) WithPayload(payload *models.StacksList) *ListCreated {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list created response
func (o *ListCreated) SetPayload(payload *models.StacksList) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListCreated) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(201)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*ListDefault error

swagger:response listDefault
*/
type ListDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Error `json:"body,omitempty"`
}

// NewListDefault creates ListDefault with default headers values
func NewListDefault(code int) *ListDefault {
	if code <= 0 {
		code = 500
	}

	return &ListDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the list default response
func (o *ListDefault) WithStatusCode(code int) *ListDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the list default response
func (o *ListDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the list default response
func (o *ListDefault) WithPayload(payload *models.Error) *ListDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list default response
func (o *ListDefault) SetPayload(payload *models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
