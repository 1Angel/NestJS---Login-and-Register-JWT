import { IsString, MaxLength, MinLength, IsEmail } from 'class-validator';


export class LoginUserDto{

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