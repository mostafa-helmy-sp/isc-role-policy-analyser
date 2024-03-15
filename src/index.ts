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
import { IdnClient } from './idn-client'
import { InherentViolation } from './model/inherent-violations'

// Connector must be exported as module property named connector
export const connector = async () => {

    // Get connector source config
    const config = await readConfig()

    // Using SailPoint's TypeScript SDK to initialize the client
    const idnClient = new IdnClient(config)

    return createConnector()
        .stdTestConnection(async (context: Context, input: StdTestConnectionInput, res: Response<StdTestConnectionOutput>) => {
            const response = await idnClient.testConnection()
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
            deltaProcessing = await idnClient.deltaProcessing(deltaProcessing, lastAggregationDate)

            logger.debug(`stdAccountList at ${state.lastAggregationDate}: Delta Processing: ${deltaProcessing}, Last Aggregation Date: ${lastAggregationDate}`)

            // Initialize metrics variables

            // Start async analysis of access profiles
            let accessProfileViolations = 0
            let inherentViolations = await idnClient.findInherentAccessProfileViolations(deltaProcessing, lastAggregationDate)
            let analysedAccessProfiles = inherentViolations.length
            for (const inherentViolation of inherentViolations) {
                // Await each analysis result, send if not null and has violated policies (i.e. inherent violation exists)
                let result: InherentViolation | undefined = await inherentViolation
                if (result && result.getViolatedPolicies() && Array.isArray(result.getViolatedPolicies()) && result.getViolatedPolicies().length > 0) {
                    res.send(result)
                    accessProfileViolations++
                }
            }
            logger.info(`stdAccountList at ${state.lastAggregationDate}: out of ${analysedAccessProfiles} analysed Access Profiles, ${accessProfileViolations} inherent violations found`)

            // Start async analysis of roles
            let roleViolations = 0
            inherentViolations = await idnClient.findInherentRoleViolations(deltaProcessing, lastAggregationDate)
            let analysedRoles = inherentViolations.length
            for (const inherentViolation of inherentViolations) {
                // Await each analysis result, send if not null (i.e. inherent violation exists)
                let result: InherentViolation | undefined = await inherentViolation
                if (result && result.getViolatedPolicies() && Array.isArray(result.getViolatedPolicies()) && result.getViolatedPolicies().length > 0) {
                    res.send(result)
                    roleViolations++
                }
            }
            logger.info(`stdAccountList at ${state.lastAggregationDate}: out of ${analysedRoles} analysed Roles, ${roleViolations} inherent violations found`)


            // Save current date for Delta Aggregation
            res.saveState(state)
        })
        .stdAccountRead(async (context: Context, input: StdAccountReadInput, res: Response<StdAccountReadOutput>) => {
            const id = (<SimpleKeyType>input.key).simple.id
            const inherentViolation = await idnClient.reprocessInherentViolation(id)
            if (inherentViolation) {
                logger.info(`stdAccountRead as ${(new Date()).toISOString()}: read account : ${input.identity}`)
                res.send(inherentViolation)
            }
        })
}