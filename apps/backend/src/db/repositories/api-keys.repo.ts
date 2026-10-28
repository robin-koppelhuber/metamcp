import { ApiKeyCreateInput, ApiKeyUpdateInput } from "@repo/zod-types";
import { and, desc, eq, inArray, isNull, or } from "drizzle-orm";
import { customAlphabet } from "nanoid";

import { db } from "../index";
import { apiKeyEndpointsTable, apiKeysTable } from "../schema";

const nanoid = customAlphabet(
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  64,
);

export class ApiKeysRepository {
  /**
   * Generate a new API key with the specified format: sk_mt_{64-char-nanoid}
   */
  private generateApiKey(): string {
    const keyPart = nanoid();
    const key = `sk_mt_${keyPart}`;

    return key;
  }

  async create(input: ApiKeyCreateInput): Promise<{
    uuid: string;
    name: string;
    key: string;
    user_id: string | null;
    created_at: Date;
  }> {
    const key = this.generateApiKey();
    // endpoint_uuids undefined = unrestricted key (default); an array = restricted to exactly those endpoints
    const endpointUuids =
      input.endpoint_uuids !== undefined
        ? [...new Set(input.endpoint_uuids)]
        : undefined;

    const createdApiKey = await db.transaction(async (tx) => {
      const [created] = await tx
        .insert(apiKeysTable)
        .values({
          name: input.name,
          key: key,
          user_id: input.user_id,
          is_active: input.is_active ?? true,
          scope_restricted: endpointUuids !== undefined,
        })
        .returning({
          uuid: apiKeysTable.uuid,
          name: apiKeysTable.name,
          user_id: apiKeysTable.user_id,
          created_at: apiKeysTable.created_at,
        });

      if (created && endpointUuids && endpointUuids.length > 0) {
        await tx.insert(apiKeyEndpointsTable).values(
          endpointUuids.map((endpointUuid) => ({
            api_key_uuid: created.uuid,
            endpoint_uuid: endpointUuid,
          })),
        );
      }

      return created;
    });

    if (!createdApiKey) {
      throw new Error("Failed to create API key");
    }

    return {
      ...createdApiKey,
      key, // Return the actual key
    };
  }

  /** Allowed endpoint uuids per API key (only meaningful for keys with scope_restricted = true). */
  private async loadAllowedEndpoints(
    keyUuids: string[],
  ): Promise<Map<string, string[]>> {
    const byKey = new Map<string, string[]>();
    if (keyUuids.length === 0) {
      return byKey;
    }

    const rows = await db
      .select({
        api_key_uuid: apiKeyEndpointsTable.api_key_uuid,
        endpoint_uuid: apiKeyEndpointsTable.endpoint_uuid,
      })
      .from(apiKeyEndpointsTable)
      .where(inArray(apiKeyEndpointsTable.api_key_uuid, keyUuids));

    for (const row of rows) {
      const list = byKey.get(row.api_key_uuid) ?? [];
      list.push(row.endpoint_uuid);
      byKey.set(row.api_key_uuid, list);
    }
    return byKey;
  }

  async findByUserId(userId: string) {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        scope_restricted: apiKeysTable.scope_restricted,
      })
      .from(apiKeysTable)
      .where(eq(apiKeysTable.user_id, userId))
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find all API keys (both public and user-owned)
  async findAll() {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find public API keys (no user ownership)
  async findPublicApiKeys() {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(isNull(apiKeysTable.user_id))
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find API keys accessible to a specific user (public + user's own keys)
  async findAccessibleToUser(userId: string) {
    const keys = await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
        scope_restricted: apiKeysTable.scope_restricted,
      })
      .from(apiKeysTable)
      .where(
        or(
          isNull(apiKeysTable.user_id), // Public API keys
          eq(apiKeysTable.user_id, userId), // User's own API keys
        ),
      )
      .orderBy(desc(apiKeysTable.created_at));

    const allowed = await this.loadAllowedEndpoints(
      keys.filter((k) => k.scope_restricted).map((k) => k.uuid),
    );

    return keys.map((k) => ({
      ...k,
      endpoint_uuids: k.scope_restricted ? (allowed.get(k.uuid) ?? []) : [],
    }));
  }

  async findByUuid(uuid: string, userId: string) {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(
        and(eq(apiKeysTable.uuid, uuid), eq(apiKeysTable.user_id, userId)),
      );

    return apiKey;
  }

  // Find API key by UUID with access control (user can access their own keys + public keys)
  async findByUuidWithAccess(uuid: string, userId?: string) {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(
        and(
          eq(apiKeysTable.uuid, uuid),
          userId
            ? or(
                isNull(apiKeysTable.user_id), // Public API keys
                eq(apiKeysTable.user_id, userId), // User's own API keys
              )
            : isNull(apiKeysTable.user_id), // Only public if no user context
        ),
      );

    return apiKey;
  }

  async validateApiKey(key: string): Promise<{
    valid: boolean;
    user_id?: string | null;
    key_uuid?: string;
    scope_restricted?: boolean;
    allowed_endpoint_uuids?: string[];
  }> {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        user_id: apiKeysTable.user_id,
        is_active: apiKeysTable.is_active,
        scope_restricted: apiKeysTable.scope_restricted,
      })
      .from(apiKeysTable)
      .where(eq(apiKeysTable.key, key));

    if (!apiKey) {
      return { valid: false };
    }

    // Check if key is active
    if (!apiKey.is_active) {
      return { valid: false };
    }

    const allowed = apiKey.scope_restricted
      ? ((await this.loadAllowedEndpoints([apiKey.uuid])).get(apiKey.uuid) ??
        [])
      : [];

    return {
      valid: true,
      user_id: apiKey.user_id,
      key_uuid: apiKey.uuid,
      scope_restricted: apiKey.scope_restricted,
      allowed_endpoint_uuids: allowed,
    };
  }

  async update(uuid: string, userId: string, input: ApiKeyUpdateInput) {
    return await db.transaction(async (tx) => {
      const [updatedApiKey] = await tx
        .update(apiKeysTable)
        .set({
          ...(input.name && { name: input.name }),
          ...(input.is_active !== undefined && { is_active: input.is_active }),
          // endpoint_uuids: null = unrestricted, array = restricted to those endpoints, undefined = unchanged
          ...(input.endpoint_uuids !== undefined && {
            scope_restricted: input.endpoint_uuids !== null,
          }),
        })
        .where(
          and(
            eq(apiKeysTable.uuid, uuid),
            or(eq(apiKeysTable.user_id, userId), isNull(apiKeysTable.user_id)),
          ),
        )
        .returning({
          uuid: apiKeysTable.uuid,
          name: apiKeysTable.name,
          key: apiKeysTable.key,
          created_at: apiKeysTable.created_at,
          is_active: apiKeysTable.is_active,
        });

      if (!updatedApiKey) {
        throw new Error("Failed to update API key or API key not found");
      }

      if (input.endpoint_uuids !== undefined) {
        await tx
          .delete(apiKeyEndpointsTable)
          .where(eq(apiKeyEndpointsTable.api_key_uuid, uuid));

        const endpointUuids = [...new Set(input.endpoint_uuids ?? [])];
        if (endpointUuids.length > 0) {
          await tx.insert(apiKeyEndpointsTable).values(
            endpointUuids.map((endpointUuid) => ({
              api_key_uuid: uuid,
              endpoint_uuid: endpointUuid,
            })),
          );
        }
      }

      return updatedApiKey;
    });
  }

  async delete(uuid: string, userId: string) {
    const [deletedApiKey] = await db
      .delete(apiKeysTable)
      .where(
        and(
          eq(apiKeysTable.uuid, uuid),
          or(eq(apiKeysTable.user_id, userId), isNull(apiKeysTable.user_id)),
        ),
      )
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
      });

    if (!deletedApiKey) {
      throw new Error("Failed to delete API key or API key not found");
    }

    return deletedApiKey;
  }
}
