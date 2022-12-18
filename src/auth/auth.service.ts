import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signUp(authDto: AuthDto) {
    try {
      // Generate the password has
      const hash = await argon.hash(authDto.password);
      // Save the new user in the db
      const user = await this.prisma.user.create({
        data: {
          email: authDto.email,
          hash,
        },
      });

      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        // Duplicated unique value
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken.');
        }
      }
    }
  }

  async signin(authDto: AuthDto) {
    try {
      // Find the user by email
      const user = await this.prisma.user.findUniqueOrThrow({
        where: {
          email: authDto.email,
        },
      });

      // Compare the password
      const pwMatches = await argon.verify(user.hash, authDto.password);
      // If password is incorrect, throw exception
      if (!pwMatches) {
        throw new Error();
      }

      return this.signToken(user.id, user.email);
    } catch (error) {
      throw new ForbiddenException('Credentials incorrect.');
    }
  }

  async signToken(userId: number, email: string): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const access_token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET'),
    });

    return { access_token };
  }
}
