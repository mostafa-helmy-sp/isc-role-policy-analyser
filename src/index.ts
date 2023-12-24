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
        .stdTestConnection(async (context: Context, input: undefined, res: Response<StdTestConnectionOutput>) => {
            const response = await idnClient.testConnection()
            if (response) {
                throw new ConnectorError(response)
            } else {
                logger.info(`Test Successful`)
                res.send({})
            }
        })
        .stdAccountList(async (context: Context, input: StdAccountListInput, res: Response<StdAccountListOutput>) => {
            let violations = 0
            await idnClient.findSimulationIdentityId()
            // Start async analysis of all roles
            let inherentViolations = await idnClient.findInherentRoleViolations()
            for (const inherentViolation of inherentViolations) {
                // Await each analysis result, send if not null (i.e. inherent violation exists)
                let result: InherentViolation | undefined = await inherentViolation
                if (result) {
                    res.send(result)
                    violations++
                }
            }
            // Start async analysis of all access profiles
            inherentViolations = await idnClient.findInherentAccessProfileViolations()
            for (const inherentViolation of inherentViolations) {
                // Await each analysis result, send if not null (i.e. inherent violation exists)
                let result: InherentViolation | undefined = await inherentViolation
                if (result) {
                    res.send(result)
                    violations++
                }
            }
            logger.info(`stdAccountList sent ${violations} accounts`)
        })
}