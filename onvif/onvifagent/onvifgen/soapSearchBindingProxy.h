/* soapSearchBindingProxy.h
   Generated by gSOAP 2.7.17 from onvif.h
   Copyright(C) 2000-2010, Robert van Engelen, Genivia Inc. All Rights Reserved.
   This part of the software is released under one of the following licenses:
   GPL, the gSOAP public license, or Genivia's license for commercial use.
*/

#ifndef soapSearchBindingProxy_H
#define soapSearchBindingProxy_H
#include "soapH.h"

class SOAP_CMAC SearchBindingProxy : public soap
{ public:
	/// Endpoint URL of service 'SearchBindingProxy' (change as needed)
	const char *soap_endpoint;
	/// Constructor
	SearchBindingProxy();
	/// Constructor with copy of another engine state
	SearchBindingProxy(const struct soap&);
	/// Constructor with engine input+output mode control
	SearchBindingProxy(soap_mode iomode);
	/// Constructor with engine input and output mode control
	SearchBindingProxy(soap_mode imode, soap_mode omode);
	/// Destructor frees deserialized data
	virtual	~SearchBindingProxy();
	/// Initializer used by constructors
	virtual	void SearchBindingProxy_init(soap_mode imode, soap_mode omode);
	/// Delete all deserialized data (uses soap_destroy and soap_end)
	virtual	void destroy();
	/// Disables and removes SOAP Header from message
	virtual	void soap_noheader();
	/// Put SOAP Header in message
	virtual	void soap_header(char *wsa__MessageID, struct wsa__Relationship *wsa__RelatesTo, struct wsa__EndpointReferenceType *wsa__From, struct wsa__EndpointReferenceType *wsa__ReplyTo, struct wsa__EndpointReferenceType *wsa__FaultTo, char *wsa__To, char *wsa__Action, struct _wsse__Security *wsse__Security, char *wsa5__MessageID, struct wsa5__RelatesToType *wsa5__RelatesTo, struct wsa5__EndpointReferenceType *wsa5__From, struct wsa5__EndpointReferenceType *wsa5__ReplyTo, struct wsa5__EndpointReferenceType *wsa5__FaultTo, char *wsa5__To, char *wsa5__Action);
	/// Get SOAP Header structure (NULL when absent)
	virtual	const SOAP_ENV__Header *soap_header();
	/// Get SOAP Fault structure (NULL when absent)
	virtual	const SOAP_ENV__Fault *soap_fault();
	/// Get SOAP Fault string (NULL when absent)
	virtual	const char *soap_fault_string();
	/// Get SOAP Fault detail as string (NULL when absent)
	virtual	const char *soap_fault_detail();
	/// Force close connection (normally automatic, except for send_X ops)
	virtual	int soap_close_socket();
	/// Print fault
	virtual	void soap_print_fault(FILE*);
#ifndef WITH_LEAN
	/// Print fault to stream
	virtual	void soap_stream_fault(std::ostream&);
	/// Put fault into buffer
	virtual	char *soap_sprint_fault(char *buf, size_t len);
#endif

	/// Web service operation 'GetServiceCapabilities' (returns error code or SOAP_OK)
	virtual	int GetServiceCapabilities(_tse__GetServiceCapabilities *tse__GetServiceCapabilities, _tse__GetServiceCapabilitiesResponse *tse__GetServiceCapabilitiesResponse);

	/// Web service operation 'GetRecordingSummary' (returns error code or SOAP_OK)
	virtual	int GetRecordingSummary(_tse__GetRecordingSummary *tse__GetRecordingSummary, _tse__GetRecordingSummaryResponse *tse__GetRecordingSummaryResponse);

	/// Web service operation 'GetRecordingInformation' (returns error code or SOAP_OK)
	virtual	int GetRecordingInformation(_tse__GetRecordingInformation *tse__GetRecordingInformation, _tse__GetRecordingInformationResponse *tse__GetRecordingInformationResponse);

	/// Web service operation 'GetMediaAttributes' (returns error code or SOAP_OK)
	virtual	int GetMediaAttributes(_tse__GetMediaAttributes *tse__GetMediaAttributes, _tse__GetMediaAttributesResponse *tse__GetMediaAttributesResponse);

	/// Web service operation 'FindRecordings' (returns error code or SOAP_OK)
	virtual	int FindRecordings(_tse__FindRecordings *tse__FindRecordings, _tse__FindRecordingsResponse *tse__FindRecordingsResponse);

	/// Web service operation 'GetRecordingSearchResults' (returns error code or SOAP_OK)
	virtual	int GetRecordingSearchResults(_tse__GetRecordingSearchResults *tse__GetRecordingSearchResults, _tse__GetRecordingSearchResultsResponse *tse__GetRecordingSearchResultsResponse);

	/// Web service operation 'FindEvents' (returns error code or SOAP_OK)
	virtual	int FindEvents(_tse__FindEvents *tse__FindEvents, _tse__FindEventsResponse *tse__FindEventsResponse);

	/// Web service operation 'GetEventSearchResults' (returns error code or SOAP_OK)
	virtual	int GetEventSearchResults(_tse__GetEventSearchResults *tse__GetEventSearchResults, _tse__GetEventSearchResultsResponse *tse__GetEventSearchResultsResponse);

	/// Web service operation 'FindPTZPosition' (returns error code or SOAP_OK)
	virtual	int FindPTZPosition(_tse__FindPTZPosition *tse__FindPTZPosition, _tse__FindPTZPositionResponse *tse__FindPTZPositionResponse);

	/// Web service operation 'GetPTZPositionSearchResults' (returns error code or SOAP_OK)
	virtual	int GetPTZPositionSearchResults(_tse__GetPTZPositionSearchResults *tse__GetPTZPositionSearchResults, _tse__GetPTZPositionSearchResultsResponse *tse__GetPTZPositionSearchResultsResponse);

	/// Web service operation 'GetSearchState' (returns error code or SOAP_OK)
	virtual	int GetSearchState(_tse__GetSearchState *tse__GetSearchState, _tse__GetSearchStateResponse *tse__GetSearchStateResponse);

	/// Web service operation 'EndSearch' (returns error code or SOAP_OK)
	virtual	int EndSearch(_tse__EndSearch *tse__EndSearch, _tse__EndSearchResponse *tse__EndSearchResponse);

	/// Web service operation 'FindMetadata' (returns error code or SOAP_OK)
	virtual	int FindMetadata(_tse__FindMetadata *tse__FindMetadata, _tse__FindMetadataResponse *tse__FindMetadataResponse);

	/// Web service operation 'GetMetadataSearchResults' (returns error code or SOAP_OK)
	virtual	int GetMetadataSearchResults(_tse__GetMetadataSearchResults *tse__GetMetadataSearchResults, _tse__GetMetadataSearchResultsResponse *tse__GetMetadataSearchResultsResponse);
};
#endif