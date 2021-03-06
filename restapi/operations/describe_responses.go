// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/kabanero-io/kabanero-rest-services/models"
)

// DescribeOKCode is the HTTP code returned for type DescribeOK
const DescribeOKCode int = 200

/*DescribeOK describe stack

swagger:response describeOK
*/
type DescribeOK struct {

	/*
	  In: Body
	*/
	Payload *models.DescribeStack `json:"body,omitempty"`
}

// NewDescribeOK creates DescribeOK with default headers values
func NewDescribeOK() *DescribeOK {

	return &DescribeOK{}
}

// WithPayload adds the payload to the describe o k response
func (o *DescribeOK) WithPayload(payload *models.DescribeStack) *DescribeOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the describe o k response
func (o *DescribeOK) SetPayload(payload *models.DescribeStack) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DescribeOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DescribeInternalServerErrorCode is the HTTP code returned for type DescribeInternalServerError
const DescribeInternalServerErrorCode int = 500

/*DescribeInternalServerError describe stack error

swagger:response describeInternalServerError
*/
type DescribeInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.Message `json:"body,omitempty"`
}

// NewDescribeInternalServerError creates DescribeInternalServerError with default headers values
func NewDescribeInternalServerError() *DescribeInternalServerError {

	return &DescribeInternalServerError{}
}

// WithPayload adds the payload to the describe internal server error response
func (o *DescribeInternalServerError) WithPayload(payload *models.Message) *DescribeInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the describe internal server error response
func (o *DescribeInternalServerError) SetPayload(payload *models.Message) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DescribeInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*DescribeDefault error

swagger:response describeDefault
*/
type DescribeDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Error `json:"body,omitempty"`
}

// NewDescribeDefault creates DescribeDefault with default headers values
func NewDescribeDefault(code int) *DescribeDefault {
	if code <= 0 {
		code = 500
	}

	return &DescribeDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the describe default response
func (o *DescribeDefault) WithStatusCode(code int) *DescribeDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the describe default response
func (o *DescribeDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the describe default response
func (o *DescribeDefault) WithPayload(payload *models.Error) *DescribeDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the describe default response
func (o *DescribeDefault) SetPayload(payload *models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DescribeDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
