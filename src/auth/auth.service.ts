import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ChangePasswordDto, SignInDto, SignUpDto } from './auth.dto';


@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async signUp(signUpdto: SignUpDto): Promise<{ message: string }> { 
    const userExists = await this.usersRepository.findOne({ where: { email: signUpdto.email } });
    if (userExists) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(signUpdto.password, 10);
    const user = this.usersRepository.create({ email: signUpdto.email, password: hashedPassword });
    await this.usersRepository.save(user);
    return { message: 'User created successfully' }; 
  }

  async signIn(signInDto: SignInDto): Promise<{ accessToken: string }> { 
    const user = await this.usersRepository.findOne({ where: { email: signInDto.email } });
    if (!user || !(await bcrypt.compare(signInDto.password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { email: user.email, sub: user.id };
    const accessToken = this.jwtService.sign(payload);
    return { accessToken }; 
  }

  async changePassword(userId: number, changePasswordDto: ChangePasswordDto): Promise<{ message: string }> {
    const user = await this.usersRepository.findOne({ where: { id: userId } });
    if (!user || !(await bcrypt.compare(changePasswordDto.oldPassword, user.password))) {
      throw new UnauthorizedException('Invalid current password');
    }

    const hashedPassword = await bcrypt.hash(changePasswordDto.newPassword, 10);
    user.password = hashedPassword;
    await this.usersRepository.save(user);
    return { message: 'Password changed successfully' }; 
  }
}
