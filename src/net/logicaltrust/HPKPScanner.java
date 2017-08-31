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
	private static String INCLUDE_SUBDOMAINS = "includeSubDomains";
	
	private final IExtensionHelpers helpers;
	private final List<String> subdomains = new ArrayList<>();
	private final List<String> subdomainsReportOnly = new ArrayList<>();
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
		
		if (hasSubdomain(subdomainsReportOnly, host)) {
			return createHpkpReportIssue(url, baseRequestResponse);
		}
		
		if (hasSubdomain(subdomains, host)) {
			return null;
		}
		
		for (String header : response.getHeaders()) {
			if (startsWithCaseInsensitive(header, HPKP)) {
				verifyIncludeSubDomains(HPKP, header, subdomains, host);
				return null;
			} else if (startsWithCaseInsensitive(header, HPKP_REPORT_ONLY)) {
				verifyIncludeSubDomains(HPKP_REPORT_ONLY, header, subdomainsReportOnly, host);
				return createHpkpReportIssue(url, baseRequestResponse);
			}
		}
		return createHpkpIssue(url, baseRequestResponse);
	}
	
	private List<IScanIssue> createHpkpReportIssue(URL url, IHttpRequestResponse baseRequestResponse) {
		return createIssue("Public key pinning is only reported", url, baseRequestResponse);
	}
	
	private List<IScanIssue> createHpkpIssue(URL url, IHttpRequestResponse baseRequestResponse) {
		return createIssue("Public key pinning not enforced", url, baseRequestResponse);
	}
	
	private List<IScanIssue> createIssue(String title, URL url, IHttpRequestResponse baseRequestResponse) {
		try {
			IScanIssue issue = new HPKPScanIssue(title,
					new URL(url.getProtocol(), url.getHost(), url.getPort(), ""), 
					null, 
					baseRequestResponse.getHttpService());
			return Arrays.asList(issue);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private boolean hasSubdomain(List<String> subdomains, String host) {
		for (String subdomain : subdomains) {
			if (host.endsWith(subdomain)) {
				return true;
			}
		}
		return false;
	}
	
	private boolean startsWithCaseInsensitive(String s1, String s2) {
		return s1.regionMatches(true, 0, s2, 0, s2.length());
	}
	
	private void verifyIncludeSubDomains(String headerPrefix, String header, List<String> subdomains, String host) {
		String[] values = header.substring(headerPrefix.length()).split("; ");
		for (String v : values) {
			if (INCLUDE_SUBDOMAINS.equals(v)) {
				subdomains.add("." + host);
			}
		}
	}

	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		return null;
	}

	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return 1;
	}

}
