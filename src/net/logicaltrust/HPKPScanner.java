package net.logicaltrust;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;

public class HPKPScanner implements IScannerCheck {

	private static String HPKP = "Public-Key-Pins: ";
	private static String HPKP_REPORT_ONLY = "Public-Key-Pins-Report-Only: ";
	
	private final IExtensionHelpers helpers;
	private final List<String> domains = new ArrayList<>();

	public HPKPScanner(IExtensionHelpers helpers) {
		this.helpers = helpers;
	}
	
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		IResponseInfo response = helpers.analyzeResponse(baseRequestResponse.getResponse());
		
		IRequestInfo request = helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest());
		URL url = request.getUrl();
		
		if (!"https".equals(url.getProtocol())) {
			return null;
		}
		
		String host = url.getHost();
		
		if (domains.contains(host)) {
			return null;
		}

		domains.add(host);
		
		for (String header : response.getHeaders()) {
			if (startsWithCaseInsensitive(header, HPKP)) {
				return null;
			} else if (startsWithCaseInsensitive(header, HPKP_REPORT_ONLY)) {
				return createHpkpReportIssue(url, baseRequestResponse, baseRequestResponse);
			}
		}
		
		return createHpkpIssue(url, baseRequestResponse);
	}
	
	private List<IScanIssue> createHpkpReportIssue(URL url, IHttpRequestResponse baseRequestResponse, IHttpRequestResponse requestResponse) {
		return createIssue("Public key pinning report only", url, baseRequestResponse, new IHttpRequestResponse[] { requestResponse });
	}
	
	private List<IScanIssue> createHpkpIssue(URL url, IHttpRequestResponse baseRequestResponse) {
		return createIssue("Public key pinning not enforced", url, baseRequestResponse, null);
	}
	
	private List<IScanIssue> createIssue(String title, URL url, IHttpRequestResponse baseRequestResponse, IHttpRequestResponse[] httpMessages) {
		try {
			IScanIssue issue = new HPKPScanIssue(title,
					new URL(url.getProtocol(), url.getHost(), url.getPort(), ""), 
					httpMessages, 
					baseRequestResponse.getHttpService());
			return Arrays.asList(issue);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private boolean startsWithCaseInsensitive(String s1, String s2) {
		return s1.regionMatches(true, 0, s2, 0, s2.length());
	}

	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		return null;
	}

	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return 1;
	}

}
