import {
    Context,
    createConnector,
    readConfig,
    Response,
    logger,
    StdAccountListOutput,
    StdTestConnectionOutput,
    StdAccountListInput,
    ConnectorError,
    CommandState,
    StdAccountReadInput,
    StdAccountReadOutput,
    SimpleKeyType,
    StdTestConnectionInput,
} from '@sailpoint/connector-sdk'
import { IscClient } from './isc-client'
import { InherentViolation } from './model/inherent-violations'

function hasViolations(inherentViolation: InherentViolation): boolean {
    return inherentViolation.getViolatedPolicies() && Array.isArray(inherentViolation.getViolatedPolicies()) && inherentViolation.getViolatedPolicies().length > 0
}

// Connector must be exported as module property named connector
export const connector = async () => {

    // Get connector source config
    const config = await readConfig()

    // Using SailPoint's TypeScript SDK to initialize the client
    const iscClient = new IscClient(config)

    return createConnector()
        .stdTestConnection(async (context: Context, input: StdTestConnectionInput, res: Response<StdTestConnectionOutput>) => {
            const response = await iscClient.testConnection()
            if (response) {
                throw new ConnectorError(response)
            } else {
                logger.info(`Test Successful`)
                res.send({})
            }
        })
        .stdAccountList(async (context: Context, input: StdAccountListInput, res: Response<StdAccountListOutput>) => {
            // Grab current date for Delta Aggregation
            const state: CommandState = { "lastAggregationDate": (new Date()).toISOString() }

            // Initialize delta processing variables
            let deltaProcessing: boolean = false
            let lastAggregationDate: string = ""
            if (input.stateful) {
                deltaProcessing = input.stateful
            }
            if (input.state && input.state.lastAggregationDate) {
                lastAggregationDate = input.state.lastAggregationDate
            }

            // Check if delta processing is possible
            deltaProcessing = await iscClient.deltaProcessing(deltaProcessing, lastAggregationDate)

            logger.debug(`stdAccountList at ${state.lastAggregationDate}: Delta Processing: ${deltaProcessing}, Last Aggregation Date: ${lastAggregationDate}`)

            // Ensure simulation identity id is present
            await iscClient.findSimulationIdentityId()

            // Initialize metrics
            let inherentViolations: Promise<InherentViolation | undefined>[] = []
            let detectedViolations = 0
            let analysedObjects = 0

            if (iscClient.isParallelProcessing()) {
                logger.info(`stdAccountList running in parallel mode`)
            } else {
                logger.info(`stdAccountList running in serial mode`)
            }

            // Analyse required Access Profiles
            const accessProfiles = await iscClient.listAccessProfiles(deltaProcessing, lastAggregationDate)
            if (accessProfiles) {
                analysedObjects += accessProfiles.length
                for (const accessProfile of accessProfiles) {
                    if (iscClient.isParallelProcessing()) {
                        // Call analyse function asynchronously
                        inherentViolations.push(iscClient.analyseAccessProfilePolicyViolations(accessProfile))
                    } else {
                        let inherentViolation = await iscClient.analyseAccessProfilePolicyViolations(accessProfile)
                        // Only return if violation exists
                        if (inherentViolation && hasViolations(inherentViolation)) {
                            detectedViolations++
                            res.send(inherentViolation)
                        }
                    }
                }
            }

            // Analyse required Roles
            const roles = await iscClient.listRoles(deltaProcessing, lastAggregationDate)
            if (roles) {
                analysedObjects += roles.length
                for (const role of roles) {
                    if (iscClient.isParallelProcessing()) {
                        // Call analyse function asynchronously
                        inherentViolations.push(iscClient.analyseRolePolicyViolations(role))
                    } else {
                        let inherentViolation = await iscClient.analyseRolePolicyViolations(role)
                        // Only return if violation exists
                        if (inherentViolation && hasViolations(inherentViolation)) {
                            detectedViolations++
                            res.send(inherentViolation)
                        }
                    }
                }
            }

            // Re-analyze Roles that contain modified Access Profiles in case of delta processing
            if (deltaProcessing) {
                const modifiedAccessProfiles = await iscClient.listAccessProfiles(deltaProcessing, lastAggregationDate)
                if (modifiedAccessProfiles && modifiedAccessProfiles.length > 0) {
                    const modifiedRoles = await iscClient.searchRolesByAccessProfileIds(modifiedAccessProfiles)
                    if (modifiedRoles && modifiedRoles.length > 0) {
                        analysedObjects += modifiedRoles.length
                        for (const modifiedRole of modifiedRoles) {
                            if (iscClient.isParallelProcessing()) {
                                // Call analyse function asynchronously
                                inherentViolations.push(iscClient.analyseRolePolicyViolations(modifiedRole))
                            } else {
                                let inherentViolation = await iscClient.analyseRolePolicyViolations(modifiedRole)
                                // Only return if violation exists
                                if (inherentViolation && hasViolations(inherentViolation)) {
                                    detectedViolations++
                                    res.send(inherentViolation)
                                }
                            }
                        }
                    }
                }
            }

            // Await async processed items and return if violation exists
            for (const inherentViolation of inherentViolations) {
                let result = await inherentViolation
                if (result && hasViolations(result)) {
                    detectedViolations++
                    res.send(result)
                }
            }

            logger.info(`stdAccountList at ${state.lastAggregationDate}: out of ${analysedObjects} analysed Roles & Access Profiles, ${detectedViolations} inherent violations found`)

            // Save current date for Delta Aggregation
            res.saveState(state)
        })
        .stdAccountRead(async (context: Context, input: StdAccountReadInput, res: Response<StdAccountReadOutput>) => {
            const id = (input.key as SimpleKeyType).simple.id
            const inherentViolation = await iscClient.reprocessInherentViolation(id)
            if (inherentViolation) {
                logger.info(`stdAccountRead at ${(new Date()).toISOString()}: read account : ${input.identity}`)
                res.send(inherentViolation)
            }
        })
}
