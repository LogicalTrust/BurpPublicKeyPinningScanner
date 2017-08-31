package net.logicaltrust;

import java.net.URL;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

public class HPKPScanIssue implements IScanIssue {
	
	private final String issueName;
	private final IHttpRequestResponse[] httpMessages;
	private final IHttpService httpService;
	private final URL url;
	
	public HPKPScanIssue(String issueName, URL url, IHttpRequestResponse[] httpMessages, IHttpService httpService) {
		this.issueName = issueName;
		this.url = url;
		this.httpMessages = httpMessages;
		this.httpService = httpService;
	}

	public URL getUrl() {
		return url;
	}

	public String getIssueName() {
		return issueName;
	}

	public int getIssueType() {
		return 0x08000000;
	}

	public String getSeverity() {
		return "Information";
	}

	public String getConfidence() {
		return "Certain";
	}

	public String getIssueBackground() {
		return null;
	}

	public String getRemediationBackground() {
		return null;
	}

	public String getIssueDetail() {
		return null;
	}

	public String getRemediationDetail() {
		return null;
	}

	public IHttpRequestResponse[] getHttpMessages() {
		return httpMessages;
	}

	public IHttpService getHttpService() {
		return httpService;
	}

}
