import { Controller, Post, ValidationPipe, Get, UseGuards } from '@nestjs/common';
import { Body, UsePipes } from '@nestjs/common/decorators';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { CreateUserDto } from './Dtos/CreateUser.Dto';
import { LoginUserDto } from './Dtos/LoginUser.Dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @UsePipes(ValidationPipe)
  Create(@Body() createUserDto: CreateUserDto) {
    return this.authService.Create(createUserDto);
  }

  @Post('login')
  Login(@Body() loginnUserDto: LoginUserDto){
    return this.authService.Login(loginnUserDto);
  }

  @Get('private')
  @UseGuards(AuthGuard())
  RutaPrivada(){
    return "hola esta es mi ruta privaada";
  }
}
