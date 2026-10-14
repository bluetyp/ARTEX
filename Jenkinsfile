pipeline {
    agent any
    options {
        timestamps()
        disableConcurrentBuilds()
        skipDefaultCheckout(true)
        timeout(time: 90, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }
    parameters {
        booleanParam(name: 'PUBLISH', defaultValue: false, description: 'Build source and push the immutable ARM64 image')
        booleanParam(name: 'DEPLOY', defaultValue: false, description: 'Publish first, then back up and deploy to main H')
    }
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.REVISION = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
                    env.ARTEX_IMAGE = "127.0.0.1:15000/artex/app:${env.REVISION}"
                }
                sh 'git diff --check && bash -n deploy/deploy.sh deploy/backup.sh'
            }
        }
        stage('Build and publish') {
            when { expression { params.PUBLISH || params.DEPLOY } }
            steps {
                sh '''#!/bin/bash
set -euo pipefail
docker buildx build --builder hermes-central --platform linux/arm64     --build-arg REVISION="$REVISION"     --build-arg GOPROXY=https://proxy.golang.org,direct     --build-arg NPM_REGISTRY=https://registry.npmjs.org     --build-arg PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.playwright.dev     --progress plain --push -t "$ARTEX_IMAGE" .
ssh h-host "docker manifest inspect --insecure '$ARTEX_IMAGE' >/dev/null"
'''
            }
        }
        stage('Deploy pull-only') {
            when { expression { params.DEPLOY } }
            steps {
                sh '''#!/bin/bash
set -euo pipefail
RELEASE="/mnt/ebs-data/services/artex/releases/$REVISION"
ssh h-host "mkdir -p '$RELEASE'"
git archive HEAD docker-compose.prod.yml deploy | ssh h-host "tar -xf - -C '$RELEASE'"
ssh h-host "bash '$RELEASE/deploy/deploy.sh' '$REVISION' '$ARTEX_IMAGE'"
'''
            }
        }
    }
}
