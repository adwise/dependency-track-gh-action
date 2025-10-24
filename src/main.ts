import * as core from '@actions/core';
import { inspect } from 'util';
import { createOrUpdateComment } from './createOrUpdateComment';
import { DependencyTrackInputs, getProjectFindings, hasBOMAnalysisCompleted, ProjectFinding, uploadBomFileToDepndencyTrack } from './dependencyTrack';
import { findComment, FindCommentInputs } from './findComment';
import { secondsBetweenDates, sleep } from './util';

const prCommentHeader = 'Dependency track analysis';
const commentAuthor = 'github-actions[bot]';

async function run(): Promise<void> {
    try {

        // capturing inputs from github workflow task
        const dependecyTrackInputs: DependencyTrackInputs = {
            serverHostBaseUrl: core.getInput('serverHostBaseUrl'),
            apiKey: core.getInput('apikey'),
            projectName: core.getInput('projectname'),
            projectVersion: core.getInput('projectversion'),
            autoCreate: core.getInput('autocreate') != 'false',
            bomFilePath: core.getInput('bomFilePath'),
        }

        if (!dependecyTrackInputs.projectVersion) {
            throw new Error('projectVersion input is required');
        }

        if (!dependecyTrackInputs.projectName) {
            throw new Error('projectName input is required');
        }

        core.info('Using dependency track server: ' + dependecyTrackInputs.serverHostBaseUrl);
        core.info('Using project name: ' + dependecyTrackInputs.projectName);
        core.info('Using project version: ' + dependecyTrackInputs.projectVersion);
        core.info('Uploading the following BOM file to dependency track server: ' + dependecyTrackInputs.bomFilePath);

        // upload bom to dependency track server
        const bomUploadToken: string = (await uploadBomFileToDepndencyTrack(dependecyTrackInputs)).token;

        core.info('Waiting for BOM analysis to complete.');
        // call hasBOMAnalysisCompleted every second, until timeout(in seconds) and then get out
        const timeoutInSecs: number = Number(core.getInput('timeoutInSecs'));
        const start = new Date();
        let end = new Date();
        let analysisCompleted: boolean = false;
        while (!analysisCompleted && secondsBetweenDates(end, start) < timeoutInSecs) {
            core.debug('calling hasBOMAnalysisCompleted');
            analysisCompleted = await hasBOMAnalysisCompleted(dependecyTrackInputs, bomUploadToken);
            await sleep(1000);
            end = new Date();
        }

        if (!analysisCompleted) {
            throw new Error(`Bom analysis wasn't completed within timeout of ${timeoutInSecs} seconds`);
        }

        core.info('BOM analysis completed successfully.');

        // Get project vulnerability findings
        const projectFindings: ProjectFinding[] = await getProjectFindings(dependecyTrackInputs);

        if (projectFindings.length) {
            core.info('Project vulneribility findings are below. \n ' + JSON.stringify(projectFindings));
        } else {
            core.info('No project vulnerability findings found.');
        }

        // Convert projectFindings into markdown
        const commentBody: string = convertProjectFindingsToMarkdown(projectFindings);

        // create or update comment on PR
        if (core.getInput('prNumber') && core.getInput('prNumber') != '') {
            await commentOnPullRequest(commentBody);
        }

        // fail check if projectFindings have severityLevel above failOnSeverityLevel value
        const severityLevel = core.getInput('failOnSeverityLevel');
        if (severityLevel && severityLevel != '') {
            const shouldFailCheck = doesProjectHaveSeverityVuln(projectFindings, severityLevel);
            if (shouldFailCheck) {
                core.setFailed(`Found CVE vulnerabilities in project with severity level ${severityLevel} and above.`);
            }
        }
    } catch (error: any) {
        core.info(inspect(error));
        core.setFailed(error.message);
    }
}

function doesProjectHaveSeverityVuln(projectFindings: ProjectFinding[], failOnSeverityLevel: string): boolean {
    for (const projectFinding of projectFindings) {
        switch (failOnSeverityLevel.toUpperCase()) {
            case 'CRITICAL': {
                if (projectFinding.vulnerability.severity === 'CRITICAL') return true;
                break;
            }
            case 'HIGH': {
                if (projectFinding.vulnerability.severity === 'CRITICAL'
                    || projectFinding.vulnerability.severity === 'HIGH') return true;
                break;
            }
            case 'MEDIUM': {
                if (projectFinding.vulnerability.severity === 'CRITICAL'
                    || projectFinding.vulnerability.severity === 'HIGH'
                    || projectFinding.vulnerability.severity === 'MEDIUM') return true;
                break;
            }
            case 'LOW': {
                if (projectFinding.vulnerability.severity === 'CRITICAL'
                    || projectFinding.vulnerability.severity === 'HIGH'
                    || projectFinding.vulnerability.severity === 'MEDIUM'
                    || projectFinding.vulnerability.severity === 'LOW') return true;
                break;
            }
            default: {
                throw new Error(`failOnSeverityLevel is not a valid value: ${failOnSeverityLevel}. Please use one of CRITICAL, HIGH, MEDIUM or LOW`);
            }
        }
    }
    return false;
}

function convertProjectFindingsToMarkdown(projectFindings: ProjectFinding[]): string {
    let commentBody = `## ${prCommentHeader} has completed. \n`;
    if (projectFindings && projectFindings.length == 0) {
        commentBody = commentBody + 'No vulnerabilities found by dependency track server';

    } else {
        commentBody = commentBody + '| Name | Version | Group | Vulnerability | Severity | CWE| \n';
        commentBody = commentBody + '| --- | --- | --- | --- | --- | --- |\n';
        for (const projectFinding of projectFindings) {
            const name = projectFinding.component.name;
            const version = projectFinding.component.version;
            const group = projectFinding.component.group;
            const vulnerability = projectFinding.vulnerability.vulnId;
            const severity = projectFinding.vulnerability.severity;
            const cwe = (projectFinding.vulnerability.cweId) ? `${projectFinding.vulnerability.cweId} ${projectFinding.vulnerability.cweName}` : projectFinding.vulnerability.cweName;
            commentBody = `${commentBody}| ${name} | ${version} | ${group} | ${vulnerability} | ${severity} | ${cwe}| \n`
        }
    }
    return commentBody;

}

async function commentOnPullRequest(commentBody: string) {
    const inputs: FindCommentInputs = {
        token: core.getInput('token'),
        repository: core.getInput('repository'),
        issueNumber: Number(core.getInput('prNumber')),
        commentAuthor: commentAuthor,
        bodyIncludes: prCommentHeader,
        direction: 'first'  //search direction. first/last
    }
    core.debug(`Inputs: ${inspect(inputs)}`)

    const existingPRComment = await findComment(inputs)

    if (existingPRComment) {
        // update comment, by passing existing PR analysis commentId and omitting issueNumber (PR Number)
        await createOrUpdateComment({
            token: inputs.token,
            repository: inputs.repository,
            commentId: existingPRComment.id,
            body: commentBody,
            editMode: 'replace'
        });
        core.debug('PR comment with analysis results has been updated successfully.');
    } else {
        // create comment, by ommitting commentId and passing issueNumber (PR Number)
        await createOrUpdateComment({
            token: inputs.token,
            repository: inputs.repository,
            issueNumber: inputs.issueNumber,
            body: commentBody,
            editMode: 'replace'
        });
    }

}

run();