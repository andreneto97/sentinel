/** The slice of TypeORM's query runner this migration uses. */
interface QueryRunner {
  query(sql: string): Promise<unknown>;
}

/**
 * A migration that declares its rollback *above* the forward path.
 *
 * Unusual but legal, and it is the shape that proves the unit's extent starts
 * at the file's first statement rather than at `up()`: the statement on line 16
 * is a data-access call site, and a unit whose span began at line 20 would
 * leave it outside and let it be enumerated a second time on its own.
 */
export class DownFirst20240501000000 {
  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP TABLE "shipments"');
  }

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE TABLE "shipments" ("id" uuid PRIMARY KEY)');
  }
}
