import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2'
import { AuthDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { access } from 'fs/promises';

@Injectable()
export class AuthService {
    constructor(
        private prismaService: PrismaService,
        private jwt: JwtService,
        private config: ConfigService,
    ) { }

    async signup(dto: AuthDto) {
        try {
            const hash = await argon.hash(dto.password)

            const user = await this.prismaService.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            })

            return this.sighToken(user.id, user.email);
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken')
                }
            }

            throw error
        }
    }

    async signin(dto: AuthDto) {
        try {
            const user = await this.prismaService.user.findUnique({
                where: {
                    email: dto.email
                },
            })

            if (!user) {
                throw new ForbiddenException('Credentials taken')
            }

            const checkPassword = await argon.verify(user.hash, dto.password)

            if (!checkPassword) {
                throw new ForbiddenException('Credentials taken')
            }

            return this.sighToken(user.id, user.email);

        } catch (error) {
            throw error
        }
    }

    async sighToken(userId: number, email: string): Promise<{ access_token: string }> {
        const payload = {
            sub: userId,
            email
        }

        const secret = this.config.get('JWT_SECRET');

        const access_token = await this.jwt.signAsync(payload, {
            expiresIn: '60m',
            secret: secret
        })

        return {
            access_token: access_token
        }
    }
}
