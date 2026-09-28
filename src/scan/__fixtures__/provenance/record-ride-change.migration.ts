// Pins a module-level `const` bound to a string literal and interpolated into a
// plpgsql body from both `up()` and `down()`: the analyser has to fold it, name
// its declaration, and rank the `down()` copy below the same code in `up()`.
// `MigrationInterface` and `QueryRunner` are declared here so the fixture
// compiles with no dependency added -- the analyser reads the `implements`
// clause and the `query(...)` call, not the import.

interface QueryRunner {
  query(statement: string, parameters?: readonly unknown[]): Promise<unknown>;
}

interface MigrationInterface {
  up(queryRunner: QueryRunner): Promise<void>;
  down(queryRunner: QueryRunner): Promise<void>;
}

const table = "ride_journal";

export class AddRideJournalReturningId20240602000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
        CREATE OR REPLACE FUNCTION record_ride_change() RETURNS trigger AS
        $body$
        DECLARE
            journal_row   ${table};
            new_id INTEGER;
        BEGIN
            INSERT INTO ${table} (journal_version, ride_id, station_id, source_table, verb)
            VALUES (journal_row.journal_version, journal_row.ride_id, journal_row.station_id, journal_row.source_table, journal_row.verb)
            RETURNING id INTO new_id;
            RETURN NULL;
        END;
        $body$
        LANGUAGE plpgsql;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
        CREATE OR REPLACE FUNCTION record_ride_change() RETURNS trigger AS
        $body$
        DECLARE
            journal_row   ${table};
        BEGIN
            INSERT INTO ${table} (journal_version, ride_id, station_id, source_table, verb)
            VALUES (journal_row.journal_version, journal_row.ride_id, journal_row.station_id, journal_row.source_table, journal_row.verb);
            RETURN NULL;
        END;
        $body$
        LANGUAGE plpgsql;
    `);
  }
}
