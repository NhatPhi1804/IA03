import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UserService,
        private jwtService: JwtService
    ) { }

    async signIn(
        email: string,
        pass: string,
    ): Promise<{ access_token: string }> {
        if(email == ''){
            throw new UnauthorizedException('Email is required.');
        }
        if(pass == ''){
            throw new UnauthorizedException('Password is required.');
        }
        const user = await this.usersService.findOne(email);
        console.log(email)
        console.log(user)
        if (!user) {
            throw new UnauthorizedException('Email does not exist.');
        } else if (!(await bcrypt.compare(pass, user.password))) {
            throw new UnauthorizedException('Password is not correct.');
        }

        const payload = { sub: user.id, username: user.email };

        return {
            access_token: await this.jwtService.signAsync(payload),
        };
    }
}
