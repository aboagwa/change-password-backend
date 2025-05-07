import { Controller, Post, Body, Request, UseGuards, Patch, ValidationPipe } from '@nestjs/common'; 
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { ChangePasswordDto, SignInDto, SignUpDto } from './auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signUp(@Body(ValidationPipe) signUpDto: SignUpDto) { 
    return this.authService.signUp(signUpDto); 
  }

  @Post('signin')
  signIn(@Body(ValidationPipe) signInDto: SignInDto) { 
    return this.authService.signIn(signInDto); 
  }

  @UseGuards(AuthGuard('jwt'))
  @Patch('change-password')
  changePassword(
    @Request() req,
    @Body(ValidationPipe) changePasswordDto: ChangePasswordDto, 
  ) {
    return this.authService.changePassword(req.user.userId, changePasswordDto); 
  }
}