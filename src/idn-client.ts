import {
    logger
} from "@sailpoint/connector-sdk"
import {
    Configuration,
    ConfigurationParameters,
    SearchApi,
    Search,
    Paginator,
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
    EntitlementBeta,
    SODPolicyApi,
    SODPolicyApiListSodPoliciesRequest,
    SodPolicy,
    SodPolicyTypeEnum,
    DtoType,
    Index
} from "sailpoint-api-client"
import { InherentViolation } from "./model/inherent-violations"
import axiosRetry from "axios-retry"

// Set IDN Global Variables
var tokenUrlPath = "/oauth/token"

// Set Source Config Global Defaults
var defaultIdentityResolutionAttribute = "name"
var defaultLeft = "Left"
var defaultRight = "Right"

export class IdnClient {

    private readonly apiConfig: Configuration
    private readonly simulationIdentityName: string
    private readonly includedPolicies?: string[]
    private readonly excludedPolicies?: string[]
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
            retries: 10,
            // retryDelay: (retryCount) => { return retryCount * 2000; },
            retryDelay: (retryCount, error) => axiosRetry.exponentialDelay(retryCount, error, 2000),
            retryCondition: (error) => {
                return error.response?.status === 429;
            },
            onRetry: (retryCount, error, requestConfig) => {
                logger.debug(`Retrying API [${requestConfig.url}] due to request error: [${error}]. Try number [${retryCount}]`)
            }
        }
        // configure the rest of the source parameters
        this.simulationIdentityName = config.simulationIdentityName
        if (config.includedPolicies) {
            this.includedPolicies = config.includedPolicies
        }
        if (config.excludedPolicies) {
            this.excludedPolicies = config.excludedPolicies
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
                Index.Identities
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
                const identity = identities.data[0] as IdentityDocument
                if (identity.entitlementCount != 0) {
                    return
                } else {
                    return { id: identity.id, name: identity.name, type: identity._type.toUpperCase() }
                }
            }
        } catch (error) {
            let errorMessage = `Error finding identity using Search API ${(error as Error).message}`
            let debugMessage = `Failed Search API request: ${JSON.stringify(error)}`
            logger.error(search, errorMessage)
            logger.debug(debugMessage)
            return
        }
    }

    // Used as a second option if the specified Simulation Identity
    async findAnyZeroEntitlementIdentity(): Promise<any> {
        const searchApi = new SearchApi(this.apiConfig)
        const query = "entitlementCount:0"
        const search: Search = {
            indices: [
                Index.Identities
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
                const identity = identities.data[0] as IdentityDocument
                return { id: identity.id, name: identity.name, type: identity._type.toUpperCase() }
            }
        } catch (error) {
            let errorMessage = `Error finding identity using Search API ${(error as Error).message}`
            let debugMessage = `Failed Search API request: ${JSON.stringify(error)}`
            logger.error(search, errorMessage)
            logger.debug(debugMessage)
            return
        }
    }

    // Use either the specified simulation identity or any zero entitlement identity for simulating inherent violations
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

    // List all Policies
    async listAllPolicies(): Promise<SodPolicy[] | undefined> {
        const policyApi = new SODPolicyApi(this.apiConfig)
        const listPolicyRequest: SODPolicyApiListSodPoliciesRequest = {}
        try {
            const allPolicies = await Paginator.paginate(policyApi, policyApi.listSodPolicies)
            // Check if no policy already exists
            if (allPolicies.data) {
                return allPolicies.data
            } else {
                return
            }
        } catch (error) {
            let errorMessage = `Error listing all Policies using SOD Policy API ${(error as Error).message}`
            let debugMessage = `Failed SOD Policy API request: ${JSON.stringify(error)}`
            logger.error(listPolicyRequest, errorMessage)
            logger.debug(debugMessage)
            return
        }
    }

    // Check whether any SOD policies have been modified since the given date
    async modifiedSodPolicies(lastAggregationDate: string | undefined): Promise<boolean> {
        let modified: boolean = false
        if (lastAggregationDate) {
            // Get all policies
            const allPolicies = await this.listAllPolicies()
            if (allPolicies) {
                // Loop all policies if array returned
                for (const policy of allPolicies) {
                    // Exit and return true at the first modified SOD policy found
                    if (policy.type && policy.type == SodPolicyTypeEnum.ConflictingAccessBased && policy.modified && policy.modified >= lastAggregationDate) {
                        logger.debug(`Disabling delta processing. Found modified policy ${policy.name} at ${policy.modified}`)
                        modified = true
                        break
                    }
                }
            } else {
                // Return true if undefined due to error fetching policies
                logger.debug(`Disabling delta processing. No policy array returned ${JSON.stringify(allPolicies)}`)
                modified = true
            }
        } else {
            // Return true if no date provided
            logger.debug(`Disabling delta processing. No date provided ${lastAggregationDate}`)
            modified = true
        }
        return modified
    }

    // Delta Processing can only occur if enabled and no SOD policies have been updated
    async deltaProcessing(deltaProcessing: boolean, lastAggregationDate: string): Promise<boolean> {
        return deltaProcessing && !(await this.modifiedSodPolicies(lastAggregationDate))
    }

    // Find required Access Profiles in the environment
    async listAccessProfiles(deltaProcessing: boolean, lastAggregationDate?: string): Promise<AccessProfile[] | undefined> {
        const accessProfilesApi = new AccessProfilesApi(this.apiConfig)
        let listAccessProfilesRequest: AccessProfilesApiListAccessProfilesRequest = {}
        let parameters = {}
        if (deltaProcessing && lastAggregationDate) {
            const filter = `modified ge ${lastAggregationDate}`
            parameters = { filters: filter }
            listAccessProfilesRequest = {
                filters: filter
            }
        }
        try {
            const accessProfiles = await Paginator.paginate(accessProfilesApi, accessProfilesApi.listAccessProfiles, parameters)
            // Check if no access profiles were found
            if (accessProfiles.data.length == 0) {
                return
            } else {
                return accessProfiles.data
            }
        } catch (error) {
            let errorMessage = `Error listing Access Profiles using Access Profiles API ${(error as Error).message}`
            let debugMessage = `Failed Access Profiles API request: ${JSON.stringify(error)}`
            logger.error(listAccessProfilesRequest, errorMessage)
            logger.debug(debugMessage)
            return
        }
    }

    // Find required Roles in the environment
    async listRoles(deltaProcessing: boolean, lastAggregationDate?: string): Promise<Role[] | undefined> {
        const rolesApi = new RolesApi(this.apiConfig)
        let listRolesRequest: RolesApiListRolesRequest = {}
        let parameters = {}
        if (deltaProcessing && lastAggregationDate) {
            const filter = `modified ge ${lastAggregationDate}`
            parameters = { filters: filter }
            listRolesRequest = {
                filters: filter
            }
        }
        try {
            const roles = await Paginator.paginate(rolesApi, rolesApi.listRoles, parameters)
            // Check if no roles were found
            if (roles.data.length == 0) {
                return
            } else {
                return roles.data
            }
        } catch (error) {
            let errorMessage = `Error listing modified Roles using Roles API ${(error as Error).message}`
            let debugMessage = `Failed Roles API request: ${JSON.stringify(error)}`
            logger.error(listRolesRequest, errorMessage)
            logger.debug(debugMessage)
            return
        }
    }

    buildIdArray(items: any[]): string[] {
        let ids: string[] = []
        items.forEach(item => ids.push(item.id))
        return ids
    }

    buildIdFilter(items: any[], prefix: string, joiner: string, itemPrefix: string, suffix: string): string {
        let filter = ""
        // Add prefix if exists, e.g.: `id in ("`
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
            // Add item prefix if exists, e.g.: accessProfiles.id:
            if (itemPrefix) {
                filter += itemPrefix
            }
            filter += item.id
        }
        // Add suffix if exists, e.g.: `")`
        if (suffix) {
            filter += suffix
        }
        return filter
    }

    // Find specified Access Profiles by filter
    async listAccessProfilesByFilter(filter: string): Promise<AccessProfile[] | undefined> {
        const accessProfilesApi = new AccessProfilesApi(this.apiConfig)
        const listAccessProfilesRequest: AccessProfilesApiListAccessProfilesRequest = {
            filters: filter
        }
        try {
            const allAccessProfiles = await Paginator.paginate(accessProfilesApi, accessProfilesApi.listAccessProfiles, { filters: filter })
            // Check if no access profiles exists
            if (allAccessProfiles.data.length == 0) {
                return
            } else {
                return allAccessProfiles.data
            }
        } catch (error) {
            let errorMessage = `Error listing Access Profiles by filter using Access Profiles API ${(error as Error).message}`
            let debugMessage = `Failed Access Profiles API request: ${JSON.stringify(error)}`
            logger.error(listAccessProfilesRequest, errorMessage)
            logger.debug(debugMessage)
            return
        }
    }

    // Find specified Roles by filter
    async listRolesByFilter(filter: string): Promise<Role[] | undefined> {
        const rolesApi = new RolesApi(this.apiConfig)
        const listRolesRequest: RolesApiListRolesRequest = {
            filters: filter
        }
        try {
            const roles = await Paginator.paginate(rolesApi, rolesApi.listRoles, { filters: filter })
            // Check if no access profiles exists
            if (roles.data.length == 0) {
                return
            } else {
                return roles.data
            }
        } catch (error) {
            let errorMessage = `Error listing Roles by filter using Roles API ${(error as Error).message}`
            let debugMessage = `Failed Roles API request: ${JSON.stringify(error)}`
            logger.error(listRolesRequest, errorMessage)
            logger.debug(debugMessage)
            return
        }
    }

    // Find Roles by specified Access Profile Ids
    async searchRolesByAccessProfileIds(accessProfiles: any[]): Promise<Role[] | undefined> {
        const query = this.buildIdFilter(accessProfiles, ``, ` OR `, `accessProfiles.id:`, ``)
        const searchApi = new SearchApi(this.apiConfig)
        const search: Search = {
            indices: [
                Index.Roles
            ],
            query: {
                query: query
            },
            queryResultFilter: {
                includes: [
                    "id",
                    "name",
                    "owner",
                    "type",
                    "accessProfiles"
                ]
            },
            sort: ["id"]
        }
        try {
            const searchRoles = await Paginator.paginateSearchApi(searchApi, search)
            // Check if no roles exists
            if (!searchRoles.data || searchRoles.data.length == 0) {
                return
            } else {
                // Cast search results into Role array and return
                let roles: Role[] = []
                searchRoles.data.forEach(searchRole => { roles.push(searchRole as Role) });
                return roles
            }
        } catch (error) {
            let errorMessage = `Error listing specified Roles using Search API ${(error as Error).message}`
            let debugMessage = `Failed Search API request: ${JSON.stringify(error)}`
            logger.error(search, errorMessage)
            logger.debug(debugMessage)
            return
        }
    }

    mergeUnique(items1: any[], items2: any[]): any[] {
        return [... new Set([...items1, ...items2])]
    }

    // Aggregate effective entitlements from access profile list
    getEffectiveEntitlements(role: Role, accessProfiles: AccessProfile[]): any[] {
        // TODO - Temp workaround casting role as any, till the SDK is updated to include direct role entitlements in the Role interface
        let effectiveEntitlements: any[] = []
        if (role.entitlements) {
            effectiveEntitlements = role.entitlements
        }
        for (const accessProfile of accessProfiles) {
            // Skip Access Profiles with no entitlements
            if (accessProfile.entitlements && accessProfile.entitlements.length > 0) {
                accessProfile.entitlements.forEach(entitlement => effectiveEntitlements.push({ id: entitlement.id, name: entitlement.name, type: entitlement.type, accessProfileName: accessProfile.name }))
            }
        }
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
        } catch (error) {
            let errorMessage = `Error predicting SOD Violations using SOD Violations API ${(error as Error).message}`
            let debugMessage = `Failed SOD Violations API request: ${JSON.stringify(error)}`
            logger.error(predictSodViolationsRequest, errorMessage)
            logger.debug(debugMessage)
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
        } catch (error) {
            let errorMessage = `Error finding Entitlement by IDs using Entitlements Beta API ${(error as Error).message}`
            let debugMessage = `Failed Entitlements Beta API request: ${JSON.stringify(error)}`
            logger.error(getEntitlementRequest, errorMessage)
            logger.debug(debugMessage)
            return
        }
    }

    buildEntitlementName(entitlement: EntitlementBeta, accessProfileName?: string): string {
        let entitlementName = `${entitlement.name} (${entitlement.source?.name} - ${entitlement.sourceSchemaObjectType})`
        if (accessProfileName) {
            entitlementName += ` - from Access Profile: [${accessProfileName}]`
        } else {
            entitlementName += ` - directly`
        }
        return entitlementName
    }

    buildViolatingEntitlementName(policy: any, criteria: string, entitlement: EntitlementBeta, accessProfileName?: string): string {
        return `Policy: [${policy.name}] - ${criteria} Criteria Entitlement: [${this.buildEntitlementName(entitlement, accessProfileName)}]`
    }

    // Build the Inherent Violation Object
    async buildInherentViolationObject(object: any, type: string, effectiveEntitlements: any[], predictedSODViolations: ViolationContext[]): Promise<InherentViolation | undefined> {
        // Create basic InherentViolation object
        let inherentViolation = new InherentViolation(object, type)

        // Loop Effective Entitlements list to retrieve additional information and populated effective entitlements list
        let effectiveEntitlementNames: string[] = []
        let entitlements = new Map<string, any>()
        for (const effectiveEntitlement of effectiveEntitlements) {
            const entitlement = await this.getEntitlementById(effectiveEntitlement.id)
            if (entitlement && entitlement.id) {
                effectiveEntitlementNames.push(this.buildEntitlementName(entitlement, effectiveEntitlement.accessProfileName))
                if (entitlements.get(entitlement.id)) {
                    // Append Access Profile Name to list if the entitlement is part of multiple Access Profiles in a single Role
                    let accessProfileNames: string[] = entitlements.get(entitlement.id).accessProfileNames
                    accessProfileNames.push(effectiveEntitlement.accessProfileName)
                    entitlements.set(entitlement.id, { entitlement: entitlement, accessProfileNames: accessProfileNames })
                } else {
                    let accessProfileNames: string[] = [effectiveEntitlement.accessProfileName]
                    entitlements.set(entitlement.id, { entitlement: entitlement, accessProfileNames: accessProfileNames })
                }
            }
        }

        // Loop Predicted SOD Violations to populate violated policies and violating entitlements lists
        let violatedPolicies: string[] = []
        let violatingEntitlements: string[] = []
        for (const predictedSODViolation of predictedSODViolations) {
            // Skip policy if excluded
            if (this.excludedPolicies && predictedSODViolation.policy?.name && this.excludedPolicies.includes(predictedSODViolation.policy?.name)) {
                continue
            }
            // Skip policy if not inclusion list exists and policy is not included
            if (this.includedPolicies && this.includedPolicies.length > 0 && predictedSODViolation.policy?.name && !this.includedPolicies.includes(predictedSODViolation.policy?.name)) {
                continue
            }
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
                            for (const accessProfileName of entitlement.accessProfileNames) {
                                violatingEntitlements.push(this.buildViolatingEntitlementName(predictedSODViolation.policy, defaultLeft, entitlement.entitlement, accessProfileName))
                            }
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
                            for (const accessProfileName of entitlement.accessProfileNames) {
                                violatingEntitlements.push(this.buildViolatingEntitlementName(predictedSODViolation.policy, defaultRight, entitlement.entitlement, accessProfileName))
                            }
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

    // Analyse a single Role for inherent SOD violations
    async analyseRolePolicyViolations(role: Role): Promise<InherentViolation | undefined> {
        logger.debug(`### Analysing Role [${role.id} - ${role.name}] ###`)

        // Stop processing if the Role has no access profiles
        if (!role.accessProfiles || role.accessProfiles.length == 0) {
            logger.debug(`Skipping Role [${role.id} - ${role.name}]. No Access Profiles to cause SOD violations.`)
            logger.debug(`### Finished analysing Role [${role.id} - ${role.name}] ###`)
            return
        }

        // Fetch extended access profile details
        const filter = this.buildIdFilter(role.accessProfiles, `id in ("`, `","`, ``, `")`)
        let accessProfiles = await this.listAccessProfilesByFilter(filter)
        if (!accessProfiles) {
            logger.error(`Unable to fetch access profile details for Role [${role.id} - ${role.name}]`)
            return
        }

        // Travese access profiles to aggregate the list of effective entitlements
        let effectiveEntitlements = this.getEffectiveEntitlements(role, accessProfiles)
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
        const inherentViolation = await this.buildInherentViolationObject(role, DtoType.Role, effectiveEntitlements, predictedSODViolations)
        if (!inherentViolation) {
            return
        }
        logger.debug(`While analysing Role [${role.id} - ${role.name}], Found Inherent Violations ${JSON.stringify(inherentViolation)}`)

        // Return final Inherent Violations object
        logger.debug(`### Finished analysing Role [${role.id} - ${role.name}] ###`)
        return inherentViolation
    }

    // Analyse a single Access Profile for inherent SOD violations
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
        const inherentViolation = await this.buildInherentViolationObject(accessProfile, DtoType.AccessProfile, accessProfile.entitlements, predictedSODViolations)
        if (!inherentViolation) {
            return
        }
        logger.debug(`While analysing Access Profile [${accessProfile.id} - ${accessProfile.name}], Found Inherent Violations ${JSON.stringify(inherentViolation)}`)

        // Return final Inherent Violations object
        logger.debug(`### Finished analysing Access Profile [${accessProfile.id} - ${accessProfile.name}] ###`)
        return inherentViolation
    }

    // Main Account Aggregation function
    async findInherentAccessProfileViolations(deltaProcessing: boolean, lastAggregationDate?: string): Promise<any[]> {
        let inherentViolations: Promise<InherentViolation | undefined>[] = []
        // Ensure simulation identity id is present
        if (!this.simulationIdentityId) {
            await this.findSimulationIdentityId()
        }
        // Analyse required Access Profiles
        const accessProfiles = await this.listAccessProfiles(deltaProcessing, lastAggregationDate)
        if (accessProfiles) {
            for (const accessProfile of accessProfiles) {
                // Call analyse function asynchronously
                inherentViolations.push(this.analyseAccessProfilePolicyViolations(accessProfile))
            }
        }
        return inherentViolations
    }

    // Main Account Aggregation function
    async findInherentRoleViolations(deltaProcessing: boolean, lastAggregationDate?: string): Promise<any[]> {
        let inherentViolations: Promise<InherentViolation | undefined>[] = []
        // Ensure simulation identity id is present
        if (!this.simulationIdentityId) {
            await this.findSimulationIdentityId()
        }
        // Analyse required Roles
        const roles = await this.listRoles(deltaProcessing, lastAggregationDate)
        if (roles) {
            for (const role of roles) {
                // Call analyse function asynchronously
                inherentViolations.push(this.analyseRolePolicyViolations(role))
            }
        }
        // Re-analyze Roles that contain modified Access Profiles in case of delta processing
        if (deltaProcessing) {
            const modifiedAccessProfiles = await this.listAccessProfiles(deltaProcessing, lastAggregationDate)
            if (modifiedAccessProfiles && modifiedAccessProfiles.length > 0) {
                const modifiedRoles = await this.searchRolesByAccessProfileIds(modifiedAccessProfiles)
                if (modifiedRoles && modifiedRoles.length > 0) {
                    for (const modifiedRole of modifiedRoles) {
                        // Call analyse function asynchronously
                        inherentViolations.push(this.analyseRolePolicyViolations(modifiedRole))
                    }
                }
            }
        }
        return inherentViolations
    }

    // To be used for single account aggregation (check after remediation)
    async reprocessInherentViolation(inputId: string): Promise<InherentViolation | undefined> {
        // Breakdown input ID
        const idParts = inputId.split(":")
        if (idParts.length < 2) {
            logger.error(`Invalid ID format ${inputId}. Expected format type:id`)
            return
        }
        const type = idParts[0]
        const id = idParts[1]

        // Ensure simulation identity id is present
        if (!this.simulationIdentityId) {
            await this.findSimulationIdentityId()
        }

        // Build the filter
        let inherentViolation
        const filter = `id eq "${id}"`
        if (type == DtoType.Role) {
            const roles = await this.listRolesByFilter(filter)
            if (roles && roles.length > 0) {
                // Process the first role in the array (only expecting one result in search by ID)
                inherentViolation = await this.analyseRolePolicyViolations(roles[0])
                if (!inherentViolation) {
                    inherentViolation = new InherentViolation(roles[0], type)
                }
            }
        } else if (type == DtoType.AccessProfile) {
            const accessProfiles = await this.listAccessProfilesByFilter(filter)
            if (accessProfiles && accessProfiles.length > 0) {
                // Process the first access profile in the array (only expecting one result in search by ID)
                inherentViolation = await this.analyseAccessProfilePolicyViolations(accessProfiles[0])
                if (!inherentViolation) {
                    inherentViolation = new InherentViolation(accessProfiles[0], type)
                }
            }
        } else {
            logger.error(`Invalid type format ${type}. Expected ROLE or ACCESS_PROFILE`)
            return
        }
        return inherentViolation
    }

    async testConnection(): Promise<any> {
        await this.findSimulationIdentityId()
        if (!this.simulationIdentityId) {
            return "Unable to find a valid simulation identity with zero entitlements"
        }
        return
    }

}