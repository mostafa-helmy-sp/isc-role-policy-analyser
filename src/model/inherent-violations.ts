import { Attributes, Key, SimpleKey, StdAccountListOutput, StdAccountReadOutput } from "@sailpoint/connector-sdk"

export class InherentViolation implements StdAccountListOutput, StdAccountReadOutput {
    identity?: string | undefined
    key?: Key | undefined
    disabled?: boolean | undefined
    locked?: boolean | undefined
    deleted?: boolean | undefined
    attributes: Attributes

    constructor(object: any, type: string) {
        this.identity = `${type}: ${object.name}`
        this.key = SimpleKey(`${type}:${object.id}`)
        this.attributes = {
            id: this.key.simple.id,
            displayName: this.identity,
            objectId: object.id,
            objectName: object.name,
            objectType: type,
            objectDescription: object.description,
            objectOwnerId: object.owner.id,
            objectOwnerName: object.owner.name,
            effectiveEntitlements: [],
            violatedPolicies: [],
            violatingEntitlements: [],
        }
    }

    getEffectiveEntitlements(): any {
        return this.attributes.effectiveEntitlements
    }

    setEffectiveEntitlements(effectiveEntitlements: string[]) {
        this.attributes.effectiveEntitlements = effectiveEntitlements
    }

    getViolatedPolicies(): any {
        return this.attributes.violatedPolicies
    }

    setViolatedPolicies(violatedPolicies: string[]) {
        this.attributes.violatedPolicies = violatedPolicies
    }

    getViolatingEntitlements(): any {
        return this.attributes.violatingEntitlements
    }

    setViolatingEntitlements(violatingEntitlements: string[]) {
        this.attributes.violatingEntitlements = violatingEntitlements
    }
}