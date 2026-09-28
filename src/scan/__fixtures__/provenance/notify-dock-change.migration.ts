// Pins a statement that comes back from a local helper which interpolates one
// field of an imported configuration module: the analyser has to inline the
// helper, name the field and the module it is read from, and hand the policy a
// `config` verdict rather than a closed one. `MigrationInterface` and
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

import config from "@fleet/config";

function getNotifyCall() {
  return `
    PERFORM pg_notify('${config.DOCK_EVENT_CHANNEL}', payload::text);

    RETURN NULL;
  `;
}

export class NotifyDockStateChange20240601000000 implements MigrationInterface {
  name = "NotifyDockStateChange20240601000000";

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE OR REPLACE FUNCTION notify_dock_change() RETURNS trigger AS
      $body$
      DECLARE
          payload          json;
      BEGIN
          IF (TG_OP = 'UPDATE' AND TG_LEVEL = 'ROW') THEN
              ${getNotifyCall()}
          ELSE
              RETURN NULL;
          END IF;
      END;
      $body$
          LANGUAGE plpgsql;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query("drop function notify_dock_change();");
  }
}
