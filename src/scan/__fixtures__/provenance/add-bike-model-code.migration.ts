// Pins a `for...of` over a local array literal that reaches two statements from
// inside the one loop: the analyser has to resolve both sinks to the same closed
// set of literals and give them one signature. `MigrationInterface` and
// `QueryRunner` are declared here so the fixture compiles with no dependency
// added -- the analyser reads the `implements` clause and the `query(...)` call,
// not the import.

interface QueryRunner {
  query(statement: string, parameters?: readonly unknown[]): Promise<unknown>;
}

interface MigrationInterface {
  up(queryRunner: QueryRunner): Promise<void>;
  down(queryRunner: QueryRunner): Promise<void>;
}

export class AddCargoTrikeModelCode20240603000000 implements MigrationInterface {
  name = "AddCargoTrikeModelCode20240603000000";

  public async up(queryRunner: QueryRunner): Promise<void> {
    const addedModelCodes = ["cargo-trike"];

    // the model a bike row carries
    for (const code of addedModelCodes) {
      await queryRunner.query(`
        ALTER TYPE "public"."bikes_model_code_enum"
        ADD VALUE IF NOT EXISTS '${code}'
      `);

      // the same model, as a fare plan's applicable one
      await queryRunner.query(`
        ALTER TYPE "public"."fare_plans_model_code_enum"
        ADD VALUE IF NOT EXISTS '${code}'
      `);
    }
  }

  public async down(_queryRunner: QueryRunner): Promise<void> {}
}
