import { IsString, MaxLength, MinLength, IsEmail } from 'class-validator';


export class CreateUserDto {
  @IsString()
  @MinLength(4)
  @MaxLength(40)
  first_name: string;

  @IsString()
  @MinLength(4)
  @MaxLength(40)
  last_name: string;

  @IsString()
  @MinLength(4)
  @MaxLength(40)
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(4)
  @MaxLength(40)
  password: string;
}
