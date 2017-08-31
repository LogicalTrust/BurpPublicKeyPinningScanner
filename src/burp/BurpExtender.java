package burp;

import net.logicaltrust.HPKPScanner;

public class BurpExtender implements IBurpExtender {

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.registerScannerCheck(new HPKPScanner(callbacks.getHelpers()));
	}

}
