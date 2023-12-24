import {
    ConnectorError,
    logger
} from "@sailpoint/connector-sdk"
import {
    Configuration,
    ConfigurationParameters,
    SourcesApi,
    SourcesApiListSourcesRequest,
    SearchApi,
    Search,
    Paginator,
    AccountsApi,
    AccountsApiListAccountsRequest,
    RolesApi,
    AccessProfilesApi,
    RolesApiListRolesRequest,
    AccessProfilesApiListAccessProfilesRequest,
    IdentityDocument,
    Role,
    AccessProfile,
    SODViolationsApi,
    SODViolationsApiStartPredictSodViolationsRequest,
    ViolationPrediction,
    ViolationContext,
    EntitlementsBetaApi,
    EntitlementsBetaApiGetEntitlementRequest,
    EntitlementBeta
} from "sailpoint-api-client"
import { InherentViolation } from "./model/inherent-violations"

// Set IDN Global Variables
var tokenUrlPath = "/oauth/token"

// Set Source Config Global Defaults
var defaultIdentityResolutionAttribute = "name"

export class IdnClient {

    private readonly apiConfig: Configuration
    private readonly rolePolicyAnalyserSourceName: string
    private readonly simulationIdentityName: string
    private rolePolicyAnalyserSourceId?: string
    private simulationIdentityId?: string

    constructor(config: any) {
        // configure the SailPoint SDK API Client
        const ConfigurationParameters: ConfigurationParameters = {
            baseurl: config.apiUrl,
            clientId: config.clientId,
            clientSecret: config.clientSecret,
            tokenUrl: config.apiUrl + tokenUrlPath
        }
        this.apiConfig = new Configuration(ConfigurationParameters)
        this.apiConfig.retriesConfig = {
            retries: 2
        }
        // configure the rest of the source parameters
        this.simulationIdentityName = config.simulationIdentityName
        this.rolePolicyAnalyserSourceName = config.rolePolicyAnalyserSourceName
    }

    // To be used for Delta Aggregation
    async getRolePolicyAnalyserSourceId(): Promise<any> {
        // Check if Source ID is null
        if (!this.rolePolicyAnalyserSourceId) {
            let filter = `name eq "${this.rolePolicyAnalyserSourceName}"`
            // Get and set Source ID if not already set
            logger.debug("Role Policy Analyser Source ID not set, getting the ID using the Sources API")
            const sourceApi = new SourcesApi(this.apiConfig)
            const sourcesRequest: SourcesApiListSourcesRequest = {
                filters: filter
            }
            try {
                const sources = await sourceApi.listSources(sourcesRequest)
                if (sources.data.length > 0) {
                    this.rolePolicyAnalyserSourceId = sources.data[0].id
                }
            } catch (err) {
                let errorMessage = `Error retrieving Role Policy Analyser Source ID using Sources API ${JSON.stringify(err)} with request: ${JSON.stringify(sourcesRequest)}`
                logger.error(errorMessage, err)
                throw new ConnectorError(errorMessage)
            }
        }
        // Return set Source ID
        logger.debug(`Role Policy Source Id: [${this.rolePolicyAnalyserSourceId}]`)
        return this.rolePolicyAnalyserSourceId
    }

    // To be used for Delta Aggregation
    async getAllRolePolicyViolations(): Promise<any[]> {
        // Get Role Policy Analyser Source ID
        await this.getRolePolicyAnalyserSourceId()
        const filter = `sourceId eq "${this.rolePolicyAnalyserSourceId}"`
        // Use Accounts API to get the Role Policy Violations stored as accounts in the Role Policy Analyser Source
        const accountsApi = new AccountsApi(this.apiConfig)
        const accountsRequest: AccountsApiListAccountsRequest = {
            filters: filter
        }
        try {
            const accounts = await accountsApi.listAccounts(accountsRequest)
            logger.debug(`Found ${accounts.data.length} Role Policy Violations`)
            return accounts.data
        } catch (err) {
            let errorMessage = `Error retrieving Role Policy Violations from the Role Policy Analyser Source using ListAccounts API ${JSON.stringify(err)} with request: ${JSON.stringify(accountsRequest)}`
            logger.error(errorMessage, err)
            throw new ConnectorError(errorMessage)
        }
    }

    // To be used for Delta Aggregation
    async getExistingRolePolicyViolationsByName(roleName: string): Promise<any> {
        // Get Role Policy Analyser Source ID
        await this.getAllRolePolicyViolations()
        const filter = `sourceId eq "${this.rolePolicyAnalyserSourceId}" and name eq "${roleName}"`
        // Use Accounts API to get the Policy configuration stored as an account in the Policy Config Source by name
        const accountsApi = new AccountsApi(this.apiConfig)
        const accountsRequest: AccountsApiListAccountsRequest = {
            filters: filter
        }
        try {
            const accounts = await accountsApi.listAccounts(accountsRequest)
            logger.debug(`Found ${accounts.data.length} Role Policy Violations`)
            return accounts.data[0]
        } catch (err) {
            let errorMessage = `Error retrieving single Role Policy Violations from the Role Policy Analyser Source using ListAccounts API ${JSON.stringify(err)} with request: ${JSON.stringify(accountsRequest)}`
            logger.error(errorMessage, err)
            throw new ConnectorError(errorMessage)
        }
    }

    // Used to find the specified Simulation Identity
    async searchIdentityByAttribute(attribute: string, value: string): Promise<any> {
        const searchApi = new SearchApi(this.apiConfig)
        let query = ""
        if (attribute === "name" || attribute === "employeeNumber" || attribute === "id") {
            query = `${attribute}:"${value}"`
        } else {
            query = `attributes.${attribute}.exact:"${value}"`
        }
        const search: Search = {
            indices: [
                "identities"
            ],
            query: {
                query: query
            },
            queryResultFilter: {
                includes: [
                    "id",
                    "name",
                    "type",
                    "entitlementCount"
                ]
            },
            sort: ["id"]
        }
        try {
            const identities = await Paginator.paginateSearchApi(searchApi, search)
            // Check if no identity exists
            if (identities.data.length == 0) {
                return
            } else {
                // Use the first identity and ensure it has no entitlements
                const identity: IdentityDocument = identities.data[0]
                if (identity.entitlementCount != 0) {
                    return
                } else {
                    return { "id": identity.id, "name": identity.name, "type": identity._type.toUpperCase() }
                }
            }
        } catch (err) {
            let errorMessage = `Error finding identity using Search API ${JSON.stringify(err)} with request: ${JSON.stringify(search)}`
            logger.error(errorMessage, err)
            return
        }
    }

    // Used as a second option if the specified Simulation Identity
    async findAnyZeroEntitlementIdentity(): Promise<any> {
        const searchApi = new SearchApi(this.apiConfig)
        let query = "entitlementCount:0"
        const search: Search = {
            indices: [
                "identities"
            ],
            query: {
                query: query
            },
            queryResultFilter: {
                includes: [
                    "id",
                    "name",
                    "type"
                ]
            },
            sort: ["id"]
        }
        try {
            const identities = await Paginator.paginateSearchApi(searchApi, search)
            // Check if no identity exists
            if (identities.data.length == 0) {
                return
            } else {
                // Use the first identity if more than one match
                const identity: IdentityDocument = identities.data[0]
                return { "id": identity.id, "name": identity.name, "type": identity._type.toUpperCase() }
            }
        } catch (err) {
            let errorMessage = `Error finding identity using Search API ${JSON.stringify(err)} with request: ${JSON.stringify(search)}`
            logger.error(errorMessage, err)
            return
        }
    }

    async findSimulationIdentityId(): Promise<any> {
        // Find the specified simulation identity
        let simulationIdentity = await this.searchIdentityByAttribute(defaultIdentityResolutionAttribute, this.simulationIdentityName)
        // Found specified simulation identity and had 0 entitlements
        if (simulationIdentity) {
            // Return set & return Identity ID
            this.simulationIdentityId = simulationIdentity.id
            logger.debug(`Found the specified simulation identity with Id: [${this.simulationIdentityId}]`)
            return this.simulationIdentityId
        }
        // Else find any zero entitlement identity
        simulationIdentity = await this.findAnyZeroEntitlementIdentity()
        // Found specified simulation identity with 0 entitlements
        if (simulationIdentity) {
            // Return set & return Identity ID
            this.simulationIdentityId = simulationIdentity.id
            logger.debug(`Using a random simulation identity with Id: [${this.simulationIdentityId}]`)
            return this.simulationIdentityId
        }
        // Log error & return null if reached this point
        logger.error(`Unable to find a valid simulation identity with zero entitlements`)
        return
    }

    // Find all Roles in the environment
    async listAllRoles(): Promise<Role[] | undefined> {
        const rolesApi = new RolesApi(this.apiConfig)
        const listRolesRequest: RolesApiListRolesRequest = {}
        try {
            const allRoles = await rolesApi.listRoles(listRolesRequest)
            // Check if no roles exists
            if (allRoles.data.length == 0) {
                return
            } else {
                return allRoles.data
            }
        } catch (err) {
            let errorMessage = `Error listing all Roles using Roles API ${JSON.stringify(err)} with request: ${JSON.stringify(listRolesRequest)}`
            logger.error(errorMessage, err)
            return
        }
    }

    // Find all Access Profiles in the environment
    async listAllAccessProfiles(): Promise<AccessProfile[] | undefined> {
        const accessProfilesApi = new AccessProfilesApi(this.apiConfig)
        const listAccessProfilesRequest: AccessProfilesApiListAccessProfilesRequest = {}
        try {
            const allAccessProfiles = await accessProfilesApi.listAccessProfiles(listAccessProfilesRequest)
            // Check if no access profiles exists
            if (allAccessProfiles.data.length == 0) {
                return
            } else {
                return allAccessProfiles.data
            }
        } catch (err) {
            let errorMessage = `Error listing all Access Profiles using Access Profiles API ${JSON.stringify(err)} with request: ${JSON.stringify(listAccessProfilesRequest)}`
            logger.error(errorMessage, err)
            return
        }
    }

    buildIdArray(items: any[]): any[] {
        let ids: any[] = []
        items.forEach(item => ids.push(item.id))
        return ids
    }

    buildIdFilter(items: any[], prefix: string, joiner: string, suffix: string): string {
        let filter = ""
        // Add prefix, e.g.: `id in ("`
        if (prefix) {
            filter += prefix
        }
        let first = true
        for (const item of items) {
            // Add joiner first unless first item, e.g.: `","`
            if (first) {
                first = false
            } else {
                filter += joiner
            }
            filter += item.id
        }
        // Add suffix, e.g.: `")`
        if (suffix) {
            filter += suffix
        }
        return filter
    }

    // Find specified Access Profiles by Id
    async listAccessProfilesByIds(accessProfiles: any[]): Promise<any> {
        const filter = this.buildIdFilter(accessProfiles, `id in ("`, `","`, `")`)
        const accessProfilesApi = new AccessProfilesApi(this.apiConfig)
        const listAccessProfilesRequest: AccessProfilesApiListAccessProfilesRequest = {
            filters: filter
        }
        try {
            const allAccessProfiles = await accessProfilesApi.listAccessProfiles(listAccessProfilesRequest)
            // Check if no access profiles exists
            if (allAccessProfiles.data.length == 0) {
                return
            } else {
                return allAccessProfiles.data
            }
        } catch (err) {
            let errorMessage = `Error listing Access Profiles by IDs using Access Profiles API ${JSON.stringify(err)} with request: ${JSON.stringify(listAccessProfilesRequest)}`
            logger.error(errorMessage, err)
            return
        }
    }

    mergeUnique(items1: any[], items2: any[]): any[] {
        return [... new Set([...items1, ...items2])]
    }

    // Aggregate effective entitlements from access profile list
    getEffectiveEntitlements(accessProfiles: AccessProfile[]): any {
        let effectiveEntitlements: any[] = []
        for (const accessProfile of accessProfiles) {
            // Skip Access Profiles with no entitlements
            if (accessProfile.entitlements && accessProfile.entitlements.length > 0) {
                accessProfile.entitlements.forEach(entitlement => effectiveEntitlements.push({ "id": entitlement.id, "name": entitlement.name, "type": entitlement.type, "accessProfileName": accessProfile.name }))
            }
        }
        // Remove any duplicate entitlements
        effectiveEntitlements = this.mergeUnique(effectiveEntitlements, [])
        return effectiveEntitlements
    }

    // Predict SOD violations using Effective Entitlement List
    async predictSODViolations(effectiveEntitlements: any[]): Promise<ViolationContext[] | undefined> {
        const sodViolationsApi = new SODViolationsApi(this.apiConfig)
        const predictSodViolationsRequest: SODViolationsApiStartPredictSodViolationsRequest = {
            identityWithNewAccess: {
                identityId: this.simulationIdentityId as string,
                accessRefs: effectiveEntitlements
            }
        }
        try {
            const predictedSODViolations = await sodViolationsApi.startPredictSodViolations(predictSodViolationsRequest)
            // Check if no predicted SOD violations
            if (!predictedSODViolations.data.violationContexts || predictedSODViolations.data.violationContexts.length == 0) {
                return
            } else {
                predictedSODViolations as ViolationPrediction
                return predictedSODViolations.data.violationContexts
            }
        } catch (err) {
            let errorMessage = `Error predicting SOD Violations using SOD Violations API ${JSON.stringify(err)} with request: ${JSON.stringify(predictSodViolationsRequest)}`
            logger.error(errorMessage, err)
            return
        }
    }

    // Get Entitlement by Id
    async getEntitlementById(entitlementId: string): Promise<EntitlementBeta | undefined> {
        const entitlementsApi = new EntitlementsBetaApi(this.apiConfig)
        const getEntitlementRequest: EntitlementsBetaApiGetEntitlementRequest = {
            id: entitlementId
        }
        try {
            const entitlement = await entitlementsApi.getEntitlement(getEntitlementRequest)
            // Check if no entitlement exists
            if (!entitlement.data.id) {
                return
            } else {
                return entitlement.data
            }
        } catch (err) {
            let errorMessage = `Error finding Entitlement by IDs using Entitlements Beta API ${JSON.stringify(err)} with request: ${JSON.stringify(getEntitlementRequest)}`
            logger.error(errorMessage, err)
            return
        }
    }

    buildEntitlementName(entitlement: EntitlementBeta, accessProfileName?: string): string {
        let entitlementName = `${entitlement.name} (${entitlement.source?.name} - ${entitlement.sourceSchemaObjectType})`
        if (accessProfileName) {
            entitlementName += ` from Access Profile [${accessProfileName}]`
        }
        return entitlementName
    }

    buildViolatingEntitlementName(policy: any, criteria: string, entitlement: EntitlementBeta, accessProfileName?: string): string {
        return `Policy [${policy.name}] ${criteria} Criteria Entitlement: ${this.buildEntitlementName(entitlement, accessProfileName)}`
    }

    // Build the Inherent Violation Object
    async buildInherentViolationObject(object: any, type: string, effectiveEntitlements: any[], predictedSODViolations: ViolationContext[]): Promise<InherentViolation> {
        // Create basic InherentViolation object
        let inherentViolation = new InherentViolation(object, type)

        // Loop Effective Entitlements list to retrieve additional information and populated effective entitlements list
        let effectiveEntitlementNames: string[] = []
        let entitlements = new Map<string, any>()
        for (const effectiveEntitlement of effectiveEntitlements) {
            const entitlement = await this.getEntitlementById(effectiveEntitlement.id)
            if (entitlement && entitlement.id) {
                effectiveEntitlementNames.push(this.buildEntitlementName(entitlement, effectiveEntitlement.accessProfileName))
                entitlements.set(entitlement.id, {"entitlement": entitlement, "accessProfileName": effectiveEntitlement.accessProfileName})
            }
        }

        // Loop Predicted SOD Violations to populate violated policies and violating entitlements lists
        let violatedPolicies: string[] = []
        let violatingEntitlements: string[] = []
        for (const predictedSODViolation of predictedSODViolations) {
            // Append violated policy name 
            if (predictedSODViolation.policy?.name) {
                violatedPolicies.push(predictedSODViolation.policy?.name)
            }
            // Append Left Critiera violating entitlements
            if (predictedSODViolation.conflictingAccessCriteria?.leftCriteria?.criteriaList) {
                for (const leftCriteriaViolatingEntitlement of predictedSODViolation.conflictingAccessCriteria?.leftCriteria?.criteriaList) {
                    if (leftCriteriaViolatingEntitlement.id) {
                        const entitlement = entitlements.get(leftCriteriaViolatingEntitlement.id)
                        if (entitlement) {
                            violatingEntitlements.push(this.buildViolatingEntitlementName(predictedSODViolation.policy, "Left", entitlement.entitlement, entitlement.accessProfileName))
                        } else {
                            logger.error(`Unable to find violating entitlement ${JSON.stringify(leftCriteriaViolatingEntitlement)} in entitlements map`)
                        }
                    }
                }
            }
            // Append Right Critiera violating entitlements
            if (predictedSODViolation.conflictingAccessCriteria?.rightCriteria?.criteriaList) {
                for (const rightCriteriaViolatingEntitlement of predictedSODViolation.conflictingAccessCriteria?.rightCriteria?.criteriaList) {
                    if (rightCriteriaViolatingEntitlement.id) {
                        const entitlement = entitlements.get(rightCriteriaViolatingEntitlement.id)
                        if (entitlement) {
                            violatingEntitlements.push(this.buildViolatingEntitlementName(predictedSODViolation.policy, "Right", entitlement.entitlement, entitlement.accessProfileName))
                        } else {
                            logger.error(`Unable to find violating entitlement ${JSON.stringify(rightCriteriaViolatingEntitlement)} in entitlements map`)
                        }
                    }
                }
            }
        }

        // Update Inherent Violation Object & return
        inherentViolation.setEffectiveEntitlements(effectiveEntitlementNames)
        inherentViolation.setViolatedPolicies(violatedPolicies)
        inherentViolation.setViolatingEntitlements(violatingEntitlements)
        return inherentViolation
    }

    async analyseRolePolicyViolations(role: Role): Promise<InherentViolation | undefined> {
        logger.debug(`### Analysing Role [${role.id} - ${role.name}] ###`)

        // Stop processing if the Role has no access profiles
        if (!role.accessProfiles || role.accessProfiles.length == 0) {
            logger.debug(`Skipping Role [${role.id} - ${role.name}]. No Access Profiles to cause SOD violations.`)
            logger.debug(`### Finished analysing Role [${role.id} - ${role.name}] ###`)
            return
        }

        // Fetch extended access profile details
        let accessProfiles = await this.listAccessProfilesByIds(role.accessProfiles)
        if (!accessProfiles) {
            logger.error(`Unable to fetch access profile details for Role [${role.id} - ${role.name}]`)
            return
        }

        // Travese access profiles to aggregate the list of effective entitlements
        let effectiveEntitlements = this.getEffectiveEntitlements(accessProfiles)
        if (effectiveEntitlements.length < 2) {
            logger.debug(`Skipping Role [${role.id} - ${role.name}]. Not enough Entitlements to cause SOD violations.`)
            logger.debug(`### Finished analysing Role [${role.id} - ${role.name}] ###`)
            return
        }

        // Predict SOD violations
        let predictedSODViolations = await this.predictSODViolations(effectiveEntitlements)

        // Return if no SOD violations predicted
        if (!predictedSODViolations || predictedSODViolations.length == 0) {
            logger.debug(`No inherent SOD violations in Role [${role.id} - ${role.name}]`)
            logger.debug(`### Finished analysing Role [${role.id} - ${role.name}] ###`)
            return
        }

        // Build Inherent Violation object
        const inherentViolation = await this.buildInherentViolationObject(role, "ROLE", effectiveEntitlements, predictedSODViolations)
        logger.debug(`While analysing Role [${role.id} - ${role.name}], Found Inherent Violations ${JSON.stringify(inherentViolation)}`)

        // Return final Inherent Violations object
        logger.debug(`### Finished analysing Role [${role.id} - ${role.name}] ###`)
        return inherentViolation
    }

    async analyseAccessProfilePolicyViolations(accessProfile: AccessProfile): Promise<InherentViolation | undefined> {
        logger.debug(`### Analysing Access Profile [${accessProfile.id} - ${accessProfile.name}] ###`)

        // Stop processing if the Access Profile has less than 2 Entitlements
        if (!accessProfile.entitlements || accessProfile.entitlements.length < 2) {
            logger.debug(`Skipping Access Profile [${accessProfile.id} - ${accessProfile.name}]. Not enough Entitlements to cause SOD violations.`)
            logger.debug(`### Finished analysing Access Profile [${accessProfile.id} - ${accessProfile.name}] ###`)
            return
        }

        // Predict SOD violations
        let predictedSODViolations = await this.predictSODViolations(accessProfile.entitlements)

        // Return if no SOD violations predicted
        if (!predictedSODViolations || predictedSODViolations.length == 0) {
            logger.debug(`No inherent SOD violations in Access Profiles [${accessProfile.id} - ${accessProfile.name}]`)
            logger.debug(`### Finished analysing Access Profile [${accessProfile.id} - ${accessProfile.name}] ###`)
            return
        }

        // Build Inherent Violation object
        const inherentViolation = await this.buildInherentViolationObject(accessProfile, "ACCESS_PROFILE", accessProfile.entitlements, predictedSODViolations)
        logger.debug(`While analysing Access Profile [${accessProfile.id} - ${accessProfile.name}], Found Inherent Violations ${JSON.stringify(inherentViolation)}`)

        // Return final Inherent Violations object
        logger.debug(`### Finished analysing Access Profile [${accessProfile.id} - ${accessProfile.name}] ###`)
        return inherentViolation
    }

    // Main Account Aggregation function
    async findInherentRoleViolations(): Promise<any[]> {
        let inherentViolations: Promise<InherentViolation | undefined>[] = []
        // Ensure simulation identity id is present
        if (!this.simulationIdentityId) {
            await this.findSimulationIdentityId()
        }
        // Analyse all Roles
        const allRoles = await this.listAllRoles()
        if (allRoles) {
            for (const role of allRoles) {
                // Call analyse function asynchronously
                inherentViolations.push(this.analyseRolePolicyViolations(role))
            }
        }
        return inherentViolations
    }

    // Main Account Aggregation function
    async findInherentAccessProfileViolations(): Promise<any[]> {
        let inherentViolations: Promise<InherentViolation | undefined>[] = []
        // Ensure simulation identity id is present
        if (!this.simulationIdentityId) {
            await this.findSimulationIdentityId()
        }
        // Analyse all Access Profiles
        const allAccessProfiles = await this.listAllAccessProfiles()
        if (allAccessProfiles) {
            for (const accessProfile of allAccessProfiles) {
                // Call analyse function asynchronously
                inherentViolations.push(this.analyseAccessProfilePolicyViolations(accessProfile))
            }
        }
        return inherentViolations
    }

    // To be used for single account aggregation (check after remediation)
    async reprocessInherentViolation(identity: string): Promise<any> {
        return
    }

    async testConnection(): Promise<any> {
        await this.findSimulationIdentityId()
        if (!this.simulationIdentityId) {
            return "Unable to find a valid simulation identity with zero entitlements"
        }
        return
    }

}