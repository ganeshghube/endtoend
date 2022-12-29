pipeline {
  environment {
    registry = "ganeshghube23/ngnix"
    registryCredential = 'dockerhub'
    dockerImage = ''
  }
  agent any
       parameters {
         choice  choices: ["Baseline", "APIS", "Full"],
                 description: 'Type of scan that is going to perform inside the container',
                 name: 'SCAN_TYPE'
 
         string defaultValue: "https://google.com",
                 description: 'Target URL to scan',
                 name: 'TARGET'
 
         booleanParam defaultValue: true,
                 description: 'Parameter to know if wanna generate report.',
                 name: 'GENERATE_REPORT'
     }
  stages {
    stage('Cloning Git and Cleanup') {
      steps {
        sh 'rm -rf .git && rm -rf *'
        sh 'git clone https://github.com/ganeshghube/endtoend.git .'
        //sh "git clone https://github.com/ganeshghube/endtoend.git"
        //sh 'cp endtoend/* .'
        //sh 'docker stop $(docker ps -a -q)'
        //sh 'docker rm $(docker ps -a -q)'
        //sh 'docker image ls -q | xargs -I {} docker image rm -f {}'
      }
    }
    stage('Compose Anchore Scanner') {
      steps {
        sh '/usr/local/bin/docker-compose up -d'
        sh 'sleep 1m'
        sh '/usr/local/bin/docker-compose exec api anchore-cli system status'
      }
    }
    stage('SAST-Validate Dockerfile') {
      steps{
        //sh 'checkov -d . --framework dockerfile'
        sh 'checkov -d . --skip-check CKV_DOCKER_7 --framework dockerfile'
      }
    }
    stage('Building Image') {
      steps{
        script {
          dockerImage = docker.build registry + ":$BUILD_NUMBER"
        }
      }
    }
    stage('Deploy Image') {
      steps{
        script {
          docker.withRegistry( '', registryCredential ) {
            dockerImage.push()
          }
        }
      }
    }
    stage('Remove Unused Docker Image') {
      steps{
        sh "docker rmi $registry:$BUILD_NUMBER"
    }   
      }
	  
	 stage('SAST Scan Docker Image') {
      steps{
		writeFile file: 'anchore_images', text:"$registry:$BUILD_NUMBER"
		anchore name: 'anchore_images' , bailOnFail: false, engineRetries: '1800'
	    anchore engineCredentialsId: 'anchoreengine', engineurl: 'http://localhost:8228/v1', forceAnalyze: true, name: 'anchore_images'
		}
    }
	stage('Remove Running Pods') {
      steps{
		 //sh "kubectl delete pods,services,deployments,svc --all"
		 sh "pwd"
		}
    }
	stage('Pipeline Info') {
                 steps {
                     script {
                         echo "<--Parameter Initialization-->"
                         echo """
                         The current parameters are:
                             Scan Type: ${params.SCAN_TYPE}
                             Target: ${params.TARGET}
                             Generate report: ${params.GENERATE_REPORT}
                         """
                     }
                 }
         }
	stage('Setting up OWASP ZAP docker container') {
             steps {
                 script {
                         echo "Pulling up last OWASP ZAP container --> Start"
                         sh 'docker pull owasp/zap2docker-stable'
                         echo "Pulling up last VMS container --> End"
                         echo "Starting container --> Start"
                         sh """
                         docker run -dt --name owasp \
                         owasp/zap2docker-stable \
                         /bin/bash
                         """
                 }
             }
         }
	stage('Prepare wrk directory') {
             when {
                         environment name : 'GENERATE_REPORT', value: 'true'
             }
             steps {
                 script {
                         sh """
                             docker exec owasp \
                             mkdir /zap/wrk
                         """
                     }
                 }
         }
	stage('Scanning target on owasp container') {
             steps {
                 script {
                     scan_type = "${params.SCAN_TYPE}"
                     echo "----> scan_type: $scan_type"
                     target = "${params.TARGET}"
                     if(scan_type == "Baseline"){
                         sh """
                             docker exec owasp \
                             zap-baseline.py \
                             -t $target \
                             -x report.xml \
                             -r scan-report.html \
                             -I
                         """
                     }
                     else if(scan_type == "APIS"){
                         sh """
                             docker exec owasp \
                             zap-api-scan.py \
                             -t $target \
                             -x report.xml \
                             -I
                         """
                     }
                     else if(scan_type == "Full"){
                         sh """
                             docker exec owasp \
                             zap-full-scan.py \
                             -t $target \
                             //-x report.xml
                             -I
                         """
                         //-x report-$(date +%d-%b-%Y).xml
                     }
                     else{
                         echo "Something went wrong..."
                     }
                 }
             }
         }
	stage('Copy Report to Workspace'){
             steps {
                 script {
                     sh '''
                         docker cp owasp:/zap/wrk/report.xml ${WORKSPACE}/report.xml
                         docker cp owasp:/zap/wrk/scan-report.html ${WORKSPACE}/scan-report.html
                     '''
                 }
             }
         }
    stage('Remove all Dockers images and containers ') {
      steps{
        sh 'docker stop $(docker ps -a -q)'
        sh 'docker rm $(docker ps -a -q)'
        sh 'docker image ls -q | xargs -I {} docker image rm -f {}'
    }   
      }
    
}

}
