// SA-NEST-03: Safe — sensitive fields excluded from serialization
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';
import { Exclude } from 'class-transformer';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  email: string;

  @Exclude()
  @Column()
  passwordHash: string;

  @Exclude()
  @Column()
  refreshToken: string;
}
