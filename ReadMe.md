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


========

</svg>Add description</a></div></div><div align="right"><form method="post" id="disable-project" action="disable"><input name="Submit" type="submit" value="Disable Project" class="submit-button primary "></form></div><div style="float:right"></div><table style="margin-top: 1em; margin-left:1em;"><tr class="app-summary"><td><svg class="" class="" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" class="" viewBox="0 0 512 512"><title></title><path d="M448 341.37V170.61A32 32 0 00432.11 143l-152-88.46a47.94 47.94 0 00-48.24 0L79.89 143A32 32 0 0064 170.61v170.76A32 32 0 0079.89 369l152 88.46a48 48 0 0048.24 0l152-88.46A32 32 0 00448 341.37z" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="32"/><path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="32" d="M69 153.99l187 110 187-110M256 463.99v-200"/></svg></td><td style="vertical-align:middle"><a href="lastSuccessfulBuild/artifact/"><a href="lastSuccessfulBuild/artifact/">Last Successful Artifacts</a><table class="fileList"><tr><td><svg class="icon-document icon-sm" class="" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" class="" viewBox="0 0 512 512"><title></title><path d="M416 221.25V416a48 48 0 01-48 48H144a48 48 0 01-48-48V96a48 48 0 0148-48h98.75a32 32 0 0122.62 9.37l141.26 141.26a32 32 0 019.37 22.62z" fill="none" stroke="currentColor" stroke-linejoin="round" stroke-width="32"/><path d="M256 56v120a32 32 0 0032 32h120M176 288h160M176 368h160" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="32"/></svg>
</td><td><a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchore_gates.json">anchore_gates.json</a></td><td class="fileSize">243 B</td><td><a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchore_gates.json/*fingerprint*/"><svg class="icon-fingerprint icon-sm" class="" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" class="" viewBox="0 0 512 512"><title></title><path d="M390.42 75.28a10.45 10.45 0 01-5.32-1.44C340.72 50.08 302.35 40 256.35 40c-45.77 0-89.23 11.28-128.76 33.84C122 77 115.11 74.8 111.87 69a12.4 12.4 0 014.63-16.32A281.81 281.81 0 01256.35 16c49.23 0 92.23 11.28 139.39 36.48a12 12 0 014.85 16.08 11.3 11.3 0 01-10.17 6.72zm-330.79 126a11.73 11.73 0 01-6.7-2.16 12.26 12.26 0 01-2.78-16.8c22.89-33.6 52-60 86.69-78.48 72.58-38.84 165.51-39.12 238.32-.24 34.68 18.48 63.8 44.64 86.69 78a12.29 12.29 0 01-2.78 16.8 11.26 11.26 0 01-16.18-2.88c-20.8-30.24-47.15-54-78.36-70.56-66.34-35.28-151.18-35.28-217.29.24-31.44 16.8-57.79 40.8-78.59 71a10 10 0 01-9.02 5.08zM204.1 491a10.66 10.66 0 01-8.09-3.6C175.9 466.48 165 453 149.55 424c-16-29.52-24.27-65.52-24.27-104.16 0-71.28 58.71-129.36 130.84-129.36S387 248.56 387 319.84a11.56 11.56 0 11-23.11 0c0-58.08-48.32-105.36-107.72-105.36S148.4 261.76 148.4 319.84c0 34.56 7.39 66.48 21.49 92.4 14.8 27.6 25 39.36 42.77 58.08a12.67 12.67 0 010 17 12.44 12.44 0 01-8.56 3.68zm165.75-44.4c-27.51 0-51.78-7.2-71.66-21.36a129.1 129.1 0 01-55-105.36 11.57 11.57 0 1123.12 0 104.28 104.28 0 0044.84 85.44c16.41 11.52 35.6 17 58.72 17a147.41 147.41 0 0024-2.4c6.24-1.2 12.25 3.12 13.4 9.84a11.92 11.92 0 01-9.47 13.92 152.28 152.28 0 01-27.95 2.88zM323.38 496a13 13 0 01-3-.48c-36.76-10.56-60.8-24.72-86-50.4-32.37-33.36-50.16-77.76-50.16-125.28 0-38.88 31.9-70.56 71.19-70.56s71.2 31.68 71.2 70.56c0 25.68 21.5 46.56 48.08 46.56s48.08-20.88 48.08-46.56c0-90.48-75.13-163.92-167.59-163.92-65.65 0-125.75 37.92-152.79 96.72-9 19.44-13.64 42.24-13.64 67.2 0 18.72 1.61 48.24 15.48 86.64 2.32 6.24-.69 13.2-6.7 15.36a11.34 11.34 0 01-14.79-7 276.39 276.39 0 01-16.88-95c0-28.8 5.32-55 15.72-77.76 30.75-67 98.94-110.4 173.6-110.4 105.18 0 190.71 84.24 190.71 187.92 0 38.88-31.9 70.56-71.2 70.56s-71.2-31.68-71.2-70.56c.01-25.68-21.49-46.6-48.07-46.6s-48.08 20.88-48.08 46.56c0 41 15.26 79.44 43.23 108.24 22 22.56 43 35 75.59 44.4 6.24 1.68 9.71 8.4 8.09 14.64a11.39 11.39 0 01-10.87 9.16z" fill="currentColor"/></svg></a> <a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchore_gates.json/*view*/">view</a></td></tr><tr><td><svg class="icon-document icon-sm" class="" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" class="" viewBox="0 0 512 512"><title></title><path d="M416 221.25V416a48 48 0 01-48 48H144a48 48 0 01-48-48V96a48 48 0 0148-48h98.75a32 32 0 0122.62 9.37l141.26 141.26a32 32 0 019.37 22.62z" fill="none" stroke="currentColor" stroke-linejoin="round" stroke-width="32"/><path d="M256 56v120a32 32 0 0032 32h120M176 288h160M176 368h160" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="32"/></svg>
</td><td><a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchore_security.json">anchore_security.json</a></td><td class="fileSize">155 B</td><td><a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchore_security.json/*fingerprint*/"><svg class="icon-fingerprint icon-sm" class="" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" class="" viewBox="0 0 512 512"><title></title><path d="M390.42 75.28a10.45 10.45 0 01-5.32-1.44C340.72 50.08 302.35 40 256.35 40c-45.77 0-89.23 11.28-128.76 33.84C122 77 115.11 74.8 111.87 69a12.4 12.4 0 014.63-16.32A281.81 281.81 0 01256.35 16c49.23 0 92.23 11.28 139.39 36.48a12 12 0 014.85 16.08 11.3 11.3 0 01-10.17 6.72zm-330.79 126a11.73 11.73 0 01-6.7-2.16 12.26 12.26 0 01-2.78-16.8c22.89-33.6 52-60 86.69-78.48 72.58-38.84 165.51-39.12 238.32-.24 34.68 18.48 63.8 44.64 86.69 78a12.29 12.29 0 01-2.78 16.8 11.26 11.26 0 01-16.18-2.88c-20.8-30.24-47.15-54-78.36-70.56-66.34-35.28-151.18-35.28-217.29.24-31.44 16.8-57.79 40.8-78.59 71a10 10 0 01-9.02 5.08zM204.1 491a10.66 10.66 0 01-8.09-3.6C175.9 466.48 165 453 149.55 424c-16-29.52-24.27-65.52-24.27-104.16 0-71.28 58.71-129.36 130.84-129.36S387 248.56 387 319.84a11.56 11.56 0 11-23.11 0c0-58.08-48.32-105.36-107.72-105.36S148.4 261.76 148.4 319.84c0 34.56 7.39 66.48 21.49 92.4 14.8 27.6 25 39.36 42.77 58.08a12.67 12.67 0 010 17 12.44 12.44 0 01-8.56 3.68zm165.75-44.4c-27.51 0-51.78-7.2-71.66-21.36a129.1 129.1 0 01-55-105.36 11.57 11.57 0 1123.12 0 104.28 104.28 0 0044.84 85.44c16.41 11.52 35.6 17 58.72 17a147.41 147.41 0 0024-2.4c6.24-1.2 12.25 3.12 13.4 9.84a11.92 11.92 0 01-9.47 13.92 152.28 152.28 0 01-27.95 2.88zM323.38 496a13 13 0 01-3-.48c-36.76-10.56-60.8-24.72-86-50.4-32.37-33.36-50.16-77.76-50.16-125.28 0-38.88 31.9-70.56 71.19-70.56s71.2 31.68 71.2 70.56c0 25.68 21.5 46.56 48.08 46.56s48.08-20.88 48.08-46.56c0-90.48-75.13-163.92-167.59-163.92-65.65 0-125.75 37.92-152.79 96.72-9 19.44-13.64 42.24-13.64 67.2 0 18.72 1.61 48.24 15.48 86.64 2.32 6.24-.69 13.2-6.7 15.36a11.34 11.34 0 01-14.79-7 276.39 276.39 0 01-16.88-95c0-28.8 5.32-55 15.72-77.76 30.75-67 98.94-110.4 173.6-110.4 105.18 0 190.71 84.24 190.71 187.92 0 38.88-31.9 70.56-71.2 70.56s-71.2-31.68-71.2-70.56c.01-25.68-21.49-46.6-48.07-46.6s-48.08 20.88-48.08 46.56c0 41 15.26 79.44 43.23 108.24 22 22.56 43 35 75.59 44.4 6.24 1.68 9.71 8.4 8.09 14.64a11.39 11.39 0 01-10.87 9.16z" fill="currentColor"/></svg></a> <a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchore_security.json/*view*/">view</a></td></tr><tr><td><svg class="icon-document icon-sm" class="" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" class="" viewBox="0 0 512 512"><title></title><path d="M416 221.25V416a48 48 0 01-48 48H144a48 48 0 01-48-48V96a48 48 0 0148-48h98.75a32 32 0 0122.62 9.37l141.26 141.26a32 32 0 019.37 22.62z" fill="none" stroke="currentColor" stroke-linejoin="round" stroke-width="32"/><path d="M256 56v120a32 32 0 0032 32h120M176 288h160M176 368h160" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="32"/></svg>
</td><td><a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchoreengine-api-response-evaluation-1.json">anchoreengine-api-response-evaluation-1.json</a></td><td class="fileSize">12.17 KB</td><td><a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchoreengine-api-response-evaluation-1.json/*fingerprint*/"><svg class="icon-fingerprint icon-sm" class="" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" class="" viewBox="0 0 512 512"><title></title><path d="M390.42 75.28a10.45 10.45 0 01-5.32-1.44C340.72 50.08 302.35 40 256.35 40c-45.77 0-89.23 11.28-128.76 33.84C122 77 115.11 74.8 111.87 69a12.4 12.4 0 014.63-16.32A281.81 281.81 0 01256.35 16c49.23 0 92.23 11.28 139.39 36.48a12 12 0 014.85 16.08 11.3 11.3 0 01-10.17 6.72zm-330.79 126a11.73 11.73 0 01-6.7-2.16 12.26 12.26 0 01-2.78-16.8c22.89-33.6 52-60 86.69-78.48 72.58-38.84 165.51-39.12 238.32-.24 34.68 18.48 63.8 44.64 86.69 78a12.29 12.29 0 01-2.78 16.8 11.26 11.26 0 01-16.18-2.88c-20.8-30.24-47.15-54-78.36-70.56-66.34-35.28-151.18-35.28-217.29.24-31.44 16.8-57.79 40.8-78.59 71a10 10 0 01-9.02 5.08zM204.1 491a10.66 10.66 0 01-8.09-3.6C175.9 466.48 165 453 149.55 424c-16-29.52-24.27-65.52-24.27-104.16 0-71.28 58.71-129.36 130.84-129.36S387 248.56 387 319.84a11.56 11.56 0 11-23.11 0c0-58.08-48.32-105.36-107.72-105.36S148.4 261.76 148.4 319.84c0 34.56 7.39 66.48 21.49 92.4 14.8 27.6 25 39.36 42.77 58.08a12.67 12.67 0 010 17 12.44 12.44 0 01-8.56 3.68zm165.75-44.4c-27.51 0-51.78-7.2-71.66-21.36a129.1 129.1 0 01-55-105.36 11.57 11.57 0 1123.12 0 104.28 104.28 0 0044.84 85.44c16.41 11.52 35.6 17 58.72 17a147.41 147.41 0 0024-2.4c6.24-1.2 12.25 3.12 13.4 9.84a11.92 11.92 0 01-9.47 13.92 152.28 152.28 0 01-27.95 2.88zM323.38 496a13 13 0 01-3-.48c-36.76-10.56-60.8-24.72-86-50.4-32.37-33.36-50.16-77.76-50.16-125.28 0-38.88 31.9-70.56 71.19-70.56s71.2 31.68 71.2 70.56c0 25.68 21.5 46.56 48.08 46.56s48.08-20.88 48.08-46.56c0-90.48-75.13-163.92-167.59-163.92-65.65 0-125.75 37.92-152.79 96.72-9 19.44-13.64 42.24-13.64 67.2 0 18.72 1.61 48.24 15.48 86.64 2.32 6.24-.69 13.2-6.7 15.36a11.34 11.34 0 01-14.79-7 276.39 276.39 0 01-16.88-95c0-28.8 5.32-55 15.72-77.76 30.75-67 98.94-110.4 173.6-110.4 105.18 0 190.71 84.24 190.71 187.92 0 38.88-31.9 70.56-71.2 70.56s-71.2-31.68-71.2-70.56c.01-25.68-21.49-46.6-48.07-46.6s-48.08 20.88-48.08 46.56c0 41 15.26 79.44 43.23 108.24 22 22.56 43 35 75.59 44.4 6.24 1.68 9.71 8.4 8.09 14.64a11.39 11.39 0 01-10.87 9.16z" fill="currentColor"/></svg></a> <a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchoreengine-api-response-evaluation-1.json/*view*/">view</a></td></tr><tr><td><svg class="icon-document icon-sm" class="" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" class="" viewBox="0 0 512 512"><title></title><path d="M416 221.25V416a48 48 0 01-48 48H144a48 48 0 01-48-48V96a48 48 0 0148-48h98.75a32 32 0 0122.62 9.37l141.26 141.26a32 32 0 019.37 22.62z" fill="none" stroke="currentColor" stroke-linejoin="round" stroke-width="32"/><path d="M256 56v120a32 32 0 0032 32h120M176 288h160M176 368h160" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="32"/></svg>
</td><td><a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchoreengine-api-response-vulnerabilities-1.json">anchoreengine-api-response-vulnerabilities-1.json</a></td><td class="fileSize">151 B</td><td><a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchoreengine-api-response-vulnerabilities-1.json/*fingerprint*/"><svg class="icon-fingerprint icon-sm" class="" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" class="" viewBox="0 0 512 512"><title></title><path d="M390.42 75.28a10.45 10.45 0 01-5.32-1.44C340.72 50.08 302.35 40 256.35 40c-45.77 0-89.23 11.28-128.76 33.84C122 77 115.11 74.8 111.87 69a12.4 12.4 0 014.63-16.32A281.81 281.81 0 01256.35 16c49.23 0 92.23 11.28 139.39 36.48a12 12 0 014.85 16.08 11.3 11.3 0 01-10.17 6.72zm-330.79 126a11.73 11.73 0 01-6.7-2.16 12.26 12.26 0 01-2.78-16.8c22.89-33.6 52-60 86.69-78.48 72.58-38.84 165.51-39.12 238.32-.24 34.68 18.48 63.8 44.64 86.69 78a12.29 12.29 0 01-2.78 16.8 11.26 11.26 0 01-16.18-2.88c-20.8-30.24-47.15-54-78.36-70.56-66.34-35.28-151.18-35.28-217.29.24-31.44 16.8-57.79 40.8-78.59 71a10 10 0 01-9.02 5.08zM204.1 491a10.66 10.66 0 01-8.09-3.6C175.9 466.48 165 453 149.55 424c-16-29.52-24.27-65.52-24.27-104.16 0-71.28 58.71-129.36 130.84-129.36S387 248.56 387 319.84a11.56 11.56 0 11-23.11 0c0-58.08-48.32-105.36-107.72-105.36S148.4 261.76 148.4 319.84c0 34.56 7.39 66.48 21.49 92.4 14.8 27.6 25 39.36 42.77 58.08a12.67 12.67 0 010 17 12.44 12.44 0 01-8.56 3.68zm165.75-44.4c-27.51 0-51.78-7.2-71.66-21.36a129.1 129.1 0 01-55-105.36 11.57 11.57 0 1123.12 0 104.28 104.28 0 0044.84 85.44c16.41 11.52 35.6 17 58.72 17a147.41 147.41 0 0024-2.4c6.24-1.2 12.25 3.12 13.4 9.84a11.92 11.92 0 01-9.47 13.92 152.28 152.28 0 01-27.95 2.88zM323.38 496a13 13 0 01-3-.48c-36.76-10.56-60.8-24.72-86-50.4-32.37-33.36-50.16-77.76-50.16-125.28 0-38.88 31.9-70.56 71.19-70.56s71.2 31.68 71.2 70.56c0 25.68 21.5 46.56 48.08 46.56s48.08-20.88 48.08-46.56c0-90.48-75.13-163.92-167.59-163.92-65.65 0-125.75 37.92-152.79 96.72-9 19.44-13.64 42.24-13.64 67.2 0 18.72 1.61 48.24 15.48 86.64 2.32 6.24-.69 13.2-6.7 15.36a11.34 11.34 0 01-14.79-7 276.39 276.39 0 01-16.88-95c0-28.8 5.32-55 15.72-77.76 30.75-67 98.94-110.4 173.6-110.4 105.18 0 190.71 84.24 190.71 187.92 0 38.88-31.9 70.56-71.2 70.56s-71.2-31.68-71.2-70.56c.01-25.68-21.49-46.6-48.07-46.6s-48.08 20.88-48.08 46.56c0 41 15.26 79.44 43.23 108.24 22 22.56 43 35 75.59 44.4 6.24 1.68 9.71 8.4 8.09 14.64a11.39 11.39 0 01-10.87 9.16z" fill="currentColor"/></svg></a> <a href="lastSuccessfulBuild/artifact/AnchoreReport.endtoend_4/anchoreengine-api-response-vulnerabilities-1.json/*view*/">view</a></td></tr></table></a></td></tr></table><script>var timeZone = 'UTC';</script><div class="cbwf-stage-view"><div objectUrl="/job/endtoend/" fragCaption="Stage View" cbwf-controller="pipeline-staged"></div><script src='/adjuncts/d3833ded/org/jenkinsci/pipeline/stageview_adjunct.js' type='text/javascript'></script><link rel="stylesheet" href="/static/d3833ded/plugin/pipeline-stage-view/jsmodules/stageview.css"></div><table style="margin-top: 1em; margin-left: 1em;"><tr class="app-summary"><td><img src="/static/d3833ded/plugin/anchore-container-scanner/images/anchore.png"></td><td style="vertical-align:middle"><a href="lastCompletedBuild/anchore-results/">Latest Anchore Report (PASS)</a></td></tr></table><table style="margin-top: 1em; margin-left: 1em;"><tr class="app-summary"><td><img src="/static/d3833ded/plugin/anchore-container-scanner/images/anchore.png"></td><td style="vertical-align:middle"><a href="lastCompletedBuild/anchore-results/">Latest Anchore Report (PASS)</a></td></tr></table><h2 class="permalinks-header">Permalinks</h2><ul class="permalinks-list"><li class="permalink-item"><a href="lastBuild/" class="permalink-link model-link inside tl-tr">Last build (#4), 13 min ago</a></li><li class="permalink-item"><a href="lastStableBuild/" class="permalink-link model-link inside tl-tr">Last stable build (#4), 13 min ago</a></li><li class="permalink-item"><a href="lastSuccessfulBuild/" class="permalink-link model-link inside tl-tr">Last successful build (#4), 13 min ago</a></li><li class="permalink-item"><a href="lastFailedBuild/" class="permalink-link model-link inside tl-tr">Last failed build (#3), 53 min ago</a></li><li class="permalink-item"><a href="lastUnsuccessfulBuild/" class="permalink-link model-link inside tl-tr">Last unsuccessful build (#3), 53 min ago</a></li><li class="permalink-item"><a href="lastCompletedBuild/" class="permalink-link model-link inside tl-tr">Last completed build (#4), 13 min ago</a></li></ul></div></div><footer class="page-footer"><div class="container-fluid"><div class="page-footer__flex-row"><div class="page-footer__footer-id-placeholder" id="footer"></div><div class="page-footer__links rest_api hidden-xs"><a href="api/">REST API</a></div><div class="page-footer__links page-footer__links--white jenkins_ver"><a rel="noopener noreferrer" href="https://www.jenkins.io/" target="_blank">Jenkins 2.375.1</a></div></div></div></footer></body></html>
