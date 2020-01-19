package com.litmus7.river.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ResponseInfo {

    private String statusCode = "200";
    private String statusMessage = "OK";
    @JsonProperty("payload")
    private Object payload;

    public String getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(String statusCode) {
        this.statusCode = statusCode;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public void setStatusMessage(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public Object getPayload() {
        return payload;
    }

    public void setPayload(Object payload) {
        this.payload = payload;
    }
}
