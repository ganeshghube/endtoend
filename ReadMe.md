<p>Here is a list of a few tools that we can use to set up our DevSecOps pipeline.</p>

<table>
  <thead>
    <tr>
      <th>Category</th>
      <th style="text-align: left">Tools</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Threat modeling</td>
      <td style="text-align: left">
<a href="https://owasp.org/www-project-threat-dragon/" rel="nofollow" target="_blank">Threat dragon</a>, <a href="https://cairis.org/cairis/tmdocsmore/" rel="nofollow" target="_blank">Cairis</a>
</td>
    </tr>
    <tr>
      <td>Secret scan</td>
      <td style="text-align: left">
<a href="https://github.com/Yelp/detect-secrets" rel="nofollow" target="_blank">detect-secret</a>, <a href="https://github.com/zricethezav/gitleaks" rel="nofollow" target="_blank">Gitleaks</a>, <a href="https://github.com/awslabs/git-secrets" rel="nofollow" target="_blank">git-secrets</a>
</td>
    </tr>
    <tr>
      <td>SBOM scan</td>
      <td style="text-align: left">
<a href="https://github.com/anchore/syft" rel="nofollow" target="_blank">Syft</a>, <a href="https://github.com/anchore/grype" rel="nofollow" target="_blank">Grype</a>, <a href="https://github.com/aquasecurity/trivy" rel="nofollow" target="_blank">Trivy</a>, <a href="https://owasp.org/www-project-dependency-check/" rel="nofollow" target="_blank">Dependency-check</a>, <a href="https://github.com/DependencyTrack/dependency-track" rel="nofollow" target="_blank">Dependency-track</a>
</td>
    </tr>
    <tr>
      <td>SAST scan</td>
      <td style="text-align: left">
<a href="https://github.com/SonarSource/sonarqube" rel="nofollow" target="_blank">SonarQube</a>, <a href="https://checkmarx.com/product/cxsast-source-code-scanning/" rel="nofollow" target="_blank">Checkmarx</a>, <a href="https://www.veracode.com/products/binary-static-analysis-sast" rel="nofollow" target="_blank">Veracode</a>, <a href="https://www.perforce.com/products/klocwork" rel="nofollow" target="_blank">Klocwork</a>
</td>
    </tr>
    <tr>
      <td>Unit testing</td>
      <td style="text-align: left">
<a href="https://github.com/jacoco/jacoco" rel="nofollow" target="_blank">JaCoCo</a>, <a href="https://mochajs.org/" rel="nofollow" target="_blank">Mocha</a>, <a href="https://jasmine.github.io/" rel="nofollow" target="_blank">Jasmine</a>
</td>
    </tr>
    <tr>
      <td>Dockerfile scan</td>
      <td style="text-align: left">
<a href="https://github.com/bridgecrewio/checkov" rel="nofollow" target="_blank">Checkov</a>, <a href="https://docs.docker.com/engine/scan/" rel="nofollow" target="_blank">docker scan</a>
</td>
    </tr>
    <tr>
      <td>Container scan</td>
      <td style="text-align: left">
<a href="https://github.com/aquasecurity/trivy" rel="nofollow" target="_blank">Trivy</a>, <a href="https://github.com/anchore/grype" rel="nofollow" target="_blank">Grype</a>, <a href="https://github.com/quay/clair" rel="nofollow" target="_blank">Clair</a>, <a href="https://docs.docker.com/engine/scan/" rel="nofollow" target="_blank">docker scan</a>, <a href="https://www.aquasec.com/products/container-analysis/" rel="nofollow" target="_blank">Aqua scan</a>
</td>
    </tr>
    <tr>
      <td>Container signing</td>
      <td style="text-align: left">
<a href="https://github.com/sigstore/cosign" rel="nofollow" target="_blank">Cosign</a>, <a href="https://github.com/containers/skopeo" rel="nofollow" target="_blank">Skopeo</a>
</td>
    </tr>
    <tr>
      <td>Container validation</td>
      <td style="text-align: left">
<a href="https://github.com/aelsabbahy/goss" rel="nofollow" target="_blank">goss</a>, <a href="https://github.com/aelsabbahy/goss/tree/master/extras/kgoss" rel="nofollow" target="_blank">kgoss</a>
</td>
    </tr>
    <tr>
      <td>Kubernete manifest scan</td>
      <td style="text-align: left">
<a href="https://github.com/bridgecrewio/checkov" rel="nofollow" target="_blank">Checkov</a>, <a href="https://github.com/tenable/terrascan" rel="nofollow" target="_blank">Terrascan</a>, <a href="https://github.com/stackrox/kube-linter" rel="nofollow" target="_blank">KubeLinter</a>
</td>
    </tr>
    <tr>
      <td>Kubernetes manifest pre-check</td>
      <td style="text-align: left">
<a href="https://github.com/kyverno/kyverno" rel="nofollow" target="_blank">Kyverno</a>, <a href="https://www.kubewarden.io/" rel="nofollow" target="_blank">Kubewarden</a>, <a href="https://github.com/open-policy-agent/gatekeeper" rel="nofollow" target="_blank">Gatekeeper</a>
</td>
    </tr>
    <tr>
      <td>CIS scan</td>
      <td style="text-align: left">
<a href="https://github.com/aquasecurity/kube-bench" rel="nofollow" target="_blank">kube-bench</a>, <a href="https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro" rel="nofollow" target="_blank">CIS-CAT Pro</a>, <a href="https://github.com/prowler-cloud/prowler" rel="nofollow" target="_blank">Prowler</a>
</td>
    </tr>
    <tr>
      <td>IaC scan</td>
      <td style="text-align: left">
<a href="https://github.com/bridgecrewio/checkov" rel="nofollow" target="_blank">Checkov</a>, <a href="https://github.com/tenable/terrascan" rel="nofollow" target="_blank">Terrascan</a>, <a href="https://github.com/Checkmarx/kics" rel="nofollow" target="_blank">KICS</a>, <a href="https://github.com/gruntwork-io/terratest" rel="nofollow" target="_blank">Terratest</a>
</td>
    </tr>
    <tr>
      <td>API testing</td>
      <td style="text-align: left">
<a href="https://github.com/apache/jmeter" rel="nofollow" target="_blank">JMeter</a>, <a href="https://github.com/Blazemeter/taurus" rel="nofollow" target="_blank">Taurus</a>, <a href="https://www.postman.com/" rel="nofollow" target="_blank">Postman</a>, <a href="https://github.com/SmartBear/soapui" rel="nofollow" target="_blank">SoapUI</a>
</td>
    </tr>
    <tr>
      <td>DAST scan</td>
      <td style="text-align: left">
<a href="https://owasp.org/www-project-zap/" rel="nofollow" target="_blank">ZAP</a>,<a href="https://www.hcltechsw.com/appscan" rel="nofollow" target="_blank">HCL Appscan</a>, <a href="https://portswigger.net/burp" rel="nofollow" target="_blank">Burp Suite</a>, <a href="https://www.invicti.com/learn/dynamic-application-security-testing-dast/" rel="nofollow" target="_blank">Invicti</a>, <a href="https://checkmarx.com/product/application-security-platform/" rel="nofollow" target="_blank">Checkmarx</a>, <a href="https://www.rapid7.com/products/insightappsec/" rel="nofollow" target="_blank">InsightAppSec</a>
</td>
    </tr>
    <tr>
      <td>Distributed tracing</td>
      <td style="text-align: left">
<a href="https://github.com/openzipkin/zipkin" rel="nofollow" target="_blank">Zipkin</a>, <a href="https://github.com/jaegertracing/jaeger" rel="nofollow" target="_blank">Jaeger</a>
</td>
    </tr>
    <tr>
      <td>Cloud native runtime security</td>
      <td style="text-align: left">
<a href="https://github.com/falcosecurity/falco" rel="nofollow" target="_blank">Falco</a>, <a href="https://github.com/cilium/tetragon" rel="nofollow" target="_blank">Tetragon</a>, <a href="https://github.com/kubearmor/KubeArmor" rel="nofollow" target="_blank">Kubearmor</a>, <a href="https://github.com/aquasecurity/tracee" rel="nofollow" target="_blank">Tracee</a>
</td>
    </tr>
    <tr>
      <td>Service mesh</td>
      <td style="text-align: left">
<a href="https://github.com/istio/istio" rel="nofollow" target="_blank">Istio</a>, <a href="https://github.com/linkerd/linkerd2" rel="nofollow" target="_blank">Linkerd</a>, <a href="https://github.com/cilium/cilium" rel="nofollow" target="_blank">Cilium</a>, <a href="https://github.com/traefik/traefik" rel="nofollow" target="_blank">Traefik</a>
</td>
    </tr>
    <tr>
      <td>Network security scan</td>
      <td style="text-align: left">
<a href="https://github.com/nmap/nmap" rel="nofollow" target="_blank">Nmap</a>, <a href="https://github.com/wireshark/wireshark" rel="nofollow" target="_blank">Wireshark</a>, <a href="https://www.tcpdump.org/" rel="nofollow" target="_blank">tcpdump</a>, <a href="https://github.com/greenbone/openvas-scanner" rel="nofollow" target="_blank">OpenVAS</a>, <a href="https://docs.rapid7.com/metasploit/discovery-scan/" rel="nofollow" target="_blank">Metasploit</a>
</td>
    </tr>
    <tr>
      <td>Antivirus scan</td>
      <td style="text-align: left">
<a href="https://www.crowdstrike.com/products/endpoint-security/falcon-prevent-antivirus/" rel="nofollow" target="_blank">Falcon</a>, <a href="https://www.sentinelone.com/" rel="nofollow" target="_blank">SentinelOne</a>, <a href="http://www.clamav.net/" rel="nofollow" target="_blank">Clamav</a>
</td>
    </tr>
    <tr>
      <td>OS vulnerability scan</td>
      <td style="text-align: left">
<a href="https://github.com/greenbone/openvas-scanner" rel="nofollow" target="_blank">OpenVAS</a>, <a href="https://www.tenable.com/products/nessus" rel="nofollow" target="_blank">Nessus</a>, <a href="https://www.rapid7.com/products/nexpose/" rel="nofollow" target="_blank">Nexpose</a>
</td>
    </tr>
    <tr>
      <td>OS patching</td>
      <td style="text-align: left">
<a href="https://www.theforeman.org/" rel="nofollow" target="_blank">Foreman</a>, <a href="https://www.redhat.com/en/technologies/management/satellite" rel="nofollow" target="_blank">Red Hat Satellite</a>, <a href="https://www.uyuni-project.org/" rel="nofollow" target="_blank">Uyuni</a>
</td>
    </tr>
    <tr>
      <td>Pen testing</td>
      <td style="text-align: left">
<a href="https://owasp.org/www-project-zap/" rel="nofollow" target="_blank">ZAP</a>, <a href="https://www.metasploit.com/" rel="nofollow" target="_blank">Metasploit</a>, <a href="https://portswigger.net/burp" rel="nofollow" target="_blank">Burp Suite</a>
</td>
    </tr>
  </tbody>
</table>


/svg></div></div><div style="display: none;" id="no-builds" class="jenkins-pane__information">No builds</div></td></tr><tr page-entry-id="-9223372036854775804" class="build-row  single-line"><td class="build-row-cell"><div class="pane build-name"><div class="build-icon"><a href="/job/endtoend/4/console" class="build-status-link"><span style="width: 16px; height: 16px; " class="build-status-icon__wrapper icon-blue icon-sm"><span class="build-status-icon__outer"><svg viewBox="0 0 24 24" tooltip="Success &amp;gt; Console Output" focusable="false" class="svg-icon "><use href="/images/build-status/build-status-sprite.svg#build-status-static"></use></svg></span><svg viewBox="0 0 24 24" tooltip="Success &amp;gt; Console Output" focusable="false" class="svg-icon icon-blue icon-sm"><use href="/static/d3833ded/images/build-status/build-status-sprite.svg#last-successful"></use></svg></span></a></div><a update-parent-class=".build-row" href="/job/endtoend/4/" class="model-link inside build-link display-name">#4</a></div><div time="1672265880139" class="pane build-details"><a update-parent-class=".build-row" tooltip="Took 8 min 3 sec" href="/job/endtoend/4/" class="model-link inside build-link">Dec 28, 2022, 10:18 PM 
        </a></div><div class="pane build-controls"><div class="middle-align build-badge"></div></div><div class="left-bar"></div></td></tr><tr page-entry-id="-9223372036854775805" class="build-row  single-line"><td class="build-row-cell"><div class="pane build-name"><div class="build-icon"><a href="/job/endtoend/3/console" class="build-status-link"><span style="width: 16px; height: 16px; " class="build-status-icon__wrapper icon-red icon-sm"><span class="build-status-icon__outer"><svg viewBox="0 0 24 24" tooltip="Failed &amp;gt; Console Output" focusable="false" class="svg-icon "><use href="/images/build-status/build-status-sprite.svg#build-status-static"></use></svg></span><svg viewBox="0 0 24 24" tooltip="Failed &amp;gt; Console Output" focusable="false" class="svg-icon icon-red icon-sm"><use href="/static/d3833ded/images/build-status/build-status-sprite.svg#last-failed"></use></svg></span></a></div><a update-parent-class=".build-row" href="/job/endtoend/3/" class="model-link inside build-link display-name">#3</a></div><div time="1672263492916" class="pane build-details"><a update-parent-class=".build-row" tooltip="Took 3 min 50 sec" href="/job/endtoend/3/" class="model-link inside build-link">Dec 28, 2022, 9:38 PM 
        </a></div><div class="pane build-controls"><div class="middle-align build-badge"></div></div><div class="left-bar"></div></td></tr><tr page-entry-id="-9223372036854775806" class="build-row  single-line"><td class="build-row-cell"><div class="pane build-name"><div class="build-icon"><a href="/job/endtoend/2/console" class="build-status-link"><span style="width: 16px; height: 16px; " class="build-status-icon__wrapper icon-red icon-sm"><span class="build-status-icon__outer"><svg viewBox="0 0 24 24" tooltip="Failed &amp;gt; Console Output" focusable="false" class="svg-icon "><use href="/images/build-status/build-status-sprite.svg#build-status-static"></use></svg></span><svg viewBox="0 0 24 24" tooltip="Failed &amp;gt; Console Output" focusable="false" class="svg-icon icon-red icon-sm"><use href="/static/d3833ded/images/build-status/build-status-sprite.svg#last-failed"></use></svg></span></a></div><a update-parent-class=".build-row" href="/job/endtoend/2/" class="model-link inside build-link display-name">#2</a></div><div time="1672262437635" class="pane build-details"><a update-parent-class=".build-row" tooltip="Took 10 sec" href="/job/endtoend/2/" class="model-link inside build-link">Dec 28, 2022, 9:20 PM 
        </a></div><div class="pane build-controls"><div class="middle-align build-badge"></div></div><div class="left-bar"></div></td></tr><tr page-entry-id="-9223372036854775807" class="build-row  single-line"><td class="build-row-cell"><div class="pane build-name"><div class="build-icon"><a href="/job/endtoend/1/console" class="build-status-link"><span style="width: 16px; height: 16px; " class="build-status-icon__wrapper icon-red icon-sm"><span class="build-status-icon__outer"><svg viewBox="0 0 24 24" tooltip="Failed &amp;gt; Console Output" focusable="false" class="svg-icon "><use href="/images/build-status/build-status-sprite.svg#build-status-static"></use></svg></span><svg viewBox="0 0 24 24" tooltip="Failed &amp;gt; Console Output" focusable="false" class="svg-icon icon-red icon-sm"><use href="/static/d3833ded/images/build-status/build-status-sprite.svg#last-failed"></use></svg></span></a></div><a update-parent-class=".build-row" href="/job/endtoend/1/" class="model-link inside build-link display-name">#1</a></div><div time="1672262060254" class="pane build-details"><a update-parent-class=".build-row" tooltip="Took 5 min 49 sec" href="/job/endtoend/1/" class="model-link inside build-link">Dec 28, 2022, 9:14 PM 
        </a></div><div class="pane build-controls"><div class="middle-align build-badge"></div></div><div class="left-bar"></div></td></tr></table></div><div class="row"><div class="col-xs-24 pane-footer"><span class="build-rss-links"><a href="/job/endtoend/rssAll" class="build-rss-all-link"><span class="build-rss-all-icon"><svg class="" class="" aria-hidden="true" width="460px" height="460px" viewBox="0 0 460 460" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><g stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"><g transform="translate(56.440081, 56.222063)" stroke="currentColor"><path d="M51.8355914,263.237609 C60.9709503,263.260732 69.2414786,266.967806 75.2384778,272.952922 C81.2358437,278.938404 84.9594026,287.202208 85.0001926,296.338927 C84.9725106,305.421743 81.2764727,313.639618 75.3166433,319.590173 C69.3466112,325.550914 61.1050301,329.236566 52.0036901,329.237536 C42.9023476,329.238505 34.6599806,325.554606 28.6886687,319.595137 C22.7173419,313.635654 19.017079,305.400589 18.9999666,296.299365 C18.9829135,287.198016 22.6522367,278.949119 28.6011501,272.967262 C34.5402452,266.995277 42.7514145,263.282855 51.8355914,263.237609 Z" stroke-width="38" fill-rule="nonzero"></path><path d="M15.5639188,0 C189.695661,18.9886079 327.916779,157.508264 346.44594,331.777403" stroke-width="40" stroke-linecap="round"></path><path d="M16.5639188,121.777403 C126.781388,133.796328 214.269067,221.472967 225.997183,331.777403" stroke-width="40" stroke-linecap="round"></path></g></g></svg></span>
          Atom feed for all
        </a><a href="/job/endtoend/rssFailed" class="build-rss-failed-link"><span class="build-rss-failed-icon"><svg class="" class="" aria-hidden="true" width="460px" height="460px" viewBox="0 0 460 460" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><g stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"><g transform="translate(56.440081, 56.222063)" stroke="currentColor"><path d="M51.8355914,263.237609 C60.9709503,263.260732 69.2414786,266.967806 75.2384778,272.952922 C81.2358437,278.938404 84.9594026,287.202208 85.0001926,296.338927 C84.9725106,305.421743 81.2764727,313.639618 75.3166433,319.590173 C69.3466112,325.550914 61.1050301,329.236566 52.0036901,329.237536 C42.9023476,329.238505 34.6599806,325.554606 28.6886687,319.595137 C22.7173419,313.635654 19.017079,305.400589 18.9999666,296.299365 C18.9829135,287.198016 22.6522367,278.949119 28.6011501,272.967262 C34.5402452,266.995277 42.7514145,263.282855 51.8355914,263.237609 Z" stroke-width="38" fill-rule="nonzero"></path><path d="M15.5639188,0 C189.695661,18.9886079 327.916779,157.508264 346.44594,331.777403" stroke-width="40" stroke-linecap="round"></path><path d="M16.5639188,121.777403 C126.781388,133.796328 214.269067,221.472967 225.997183,331.777403" stroke-width="40" stroke-linecap="round"></path></g></g></svg></span>
          Atom feed for failures
        </a></span></div></div></div><div id="properties" page-next-build="5"></div></div><script src="/static/d3833ded/jsbundles/filter-build-history.js" type="text/javascript"></script></div><div id="main-panel"><a name="skip2content"></a><h1 class="job-index-headline page-headline">Pipeline endtoend</h1><div id="description"><div></div><div class="jenkins-buttons-row jenkins-buttons-row--invert"><a class="jenkins-button jenkins-button--tertiary" id="description-link" href="editDescription" onclick="return replaceDescription();"><?xml version="1.0" encoding="UTF-8"?>
<svg class="" class="" aria-hidden="true" width="512px" height="512px" viewBox="0 0 512 512" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <title></title>
    <g stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <path d="M399.608914,57 C413.784791,57 427.960684,62.4078333 438.776426,73.2235621 C449.592141,84.0392638 455,98.2149574 455,112.390686 C455,126.566468 449.592105,140.742274 438.776426,151.558078 L438.776426,151.558078 L191.040603,399.293596 C182.232434,408.101755 171.575528,414.840664 159.841736,419.022244 L159.841736,419.022244 L58.9309718,454.983885 C58.3980325,455.005817 57.9083807,454.793595 57.5574476,454.442654 C57.2063668,454.091565 56.9941379,453.601684 57.0161199,453.068522 L57.0161199,453.068522 L92.977296,352.157786 C97.1588787,340.423838 103.897856,329.766792 112.706129,320.958529 L112.706129,320.958529 L360.441401,73.2235621 C371.257143,62.4078333 385.433036,57 399.608914,57 Z" stroke="currentColor" stroke-width="32" fill-rule="nonzero"></path>
        <polyline fill="currentColor" transform="translate(362.692388, 154.192388) rotate(45.000000) translate(-362.692388, -154.192388) " points="308.192388 138.192388 359.945436 138.192388 417.192388 138.192388 417.192388 170.192388 360.652543 170.192388 308.192388 170.192388"></polyline>
    </g>
