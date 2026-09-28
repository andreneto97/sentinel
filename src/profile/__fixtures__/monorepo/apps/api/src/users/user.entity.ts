import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

/** Persisted user row. */
@Entity()
export class User {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column({ unique: true })
  email!: string;
}
