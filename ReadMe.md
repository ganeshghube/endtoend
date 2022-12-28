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

