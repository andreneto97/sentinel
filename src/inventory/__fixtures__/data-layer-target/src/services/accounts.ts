import { Model } from "sequelize";

/** The fixture model. */
export class Account extends Model {}

/** One tenant's accounts, bounded and projected. */
export async function accountsFor(tenantId: string) {
  return await Account.findAll({
    where: { tenantId },
    attributes: ["id", "name"],
    limit: 50,
  });
}

/** Every account, unbounded. */
export async function allAccounts() {
  return await Account.findAll({});
}
