import { Attributes, Key, Permission, SimpleKey, StdAccountListOutput } from "@sailpoint/connector-sdk"

export class InherentViolation implements StdAccountListOutput {
    identity?: string | undefined
    uuid?: string | undefined
    key?: Key | undefined
    disabled?: boolean | undefined
    locked?: boolean | undefined
    deleted?: boolean | undefined
    attributes: Attributes
    permissions?: Permission[] | undefined

    constructor(object: any, type: string) {
        this.identity = `${type}: ${object.name}`
        this.key = SimpleKey(object.id as string)
        this.attributes = {
            id: object.id,
            name: object.name,
            type: type,
            displayName: this.identity,
            description: object.description,
            ownerId: object.owner.id,
            ownerName: object.owner.name,
            effectiveEntitlements: [],
            violatedPolicies: [],
            violatingEntitlements: [],
        }
    }

    setEffectiveEntitlements(effectiveEntitlements: string[]) {
        this.attributes.effectiveEntitlements = effectiveEntitlements
    }

    addViolatedPolicy(violatedPolicies: string[]) {
        this.attributes.violatedPolicies = violatedPolicies
    }

    setViolatedPolicies(violatedPolicies: string[]) {
        this.attributes.violatedPolicies = violatedPolicies
    }

    setViolatingEntitlements(violatingEntitlements: string[]) {
        this.attributes.violatingEntitlements = violatingEntitlements
    }
}