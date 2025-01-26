## Authentication Service

### authentication.module.ts
```typescript
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { AuthenticationService } from './authentication.service';
import { User, UserSchema } from './user.schema';
import { AuthenticationController } from './authentication.controller';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'secretKey',
      signOptions: { expiresIn: '1h' },
    }),
    HttpModule
  ],
  controllers: [AuthenticationController],
  providers: [AuthenticationService],
})
export class AuthenticationModule {}
```

### authentication.service.ts
```typescript
import { Injectable, HttpService } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './user.schema';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private httpService: HttpService,
  ) {}

  async register(userData: Partial<User>) {
    const existingUser = await this.userModel.findOne({ email: userData.email });
    if (existingUser) {
      throw new Error('User already exists');
    }
    userData.password = await bcrypt.hash(userData.password, 10);
    const user = new this.userModel(userData);
    return user.save();
  }

  async login(email: string, password: string) {
    const user = await this.userModel.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new Error('Invalid credentials');
    }
    const roles = await this.fetchUserRoles(user.roles);
    const payload = { email: user.email, roles };
    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });
    return { accessToken, refreshToken };
  }

  async fetchUserRoles(roleIds: string[]): Promise<string[]> {
    try {
      const response = await this.httpService.get('http://role-service:3001/roles', {
        params: { ids: roleIds.join(',') }
      }).toPromise();
      return response.data;
    } catch (error) {
      throw new Error('Failed to fetch roles from role service');
    }
  }

  async getUserDetails(token: string) {
    const decoded = this.jwtService.verify(token);
    return this.userModel.findOne({ email: decoded.email });
  }
}
```

### authentication.controller.ts
```typescript
import { Controller, Post, Body, Get, Headers } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';

@Controller('auth')
export class AuthenticationController {
  constructor(private readonly authService: AuthenticationService) {}

  @Post('register')
  async register(@Body() body: Partial<User>) {
    return this.authService.register(body);
  }

  @Post('login')
  async login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }

  @Get('user-details')
  async getUserDetails(@Headers('x-auth-token') token: string) {
    return this.authService.getUserDetails(token);
  }
}
```

### user.schema.ts
```typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class User {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ required: true })
  firstName: string;

  @Prop({ required: true })
  lastName: string;

  @Prop()
  address: string;

  @Prop({ required: true })
  contactNumber: string;

  @Prop({ default: true })
  activeStatus: boolean;

  @Prop({ type: [String], default: [] })
  roles: string[];
}

export type UserDocument = User & Document;
export const UserSchema = SchemaFactory.createForClass(User);
```
