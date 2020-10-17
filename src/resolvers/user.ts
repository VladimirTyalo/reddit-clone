import { MyContext } from "src/types";
import { User } from "../entities/User";
import {
  Resolver,
  Mutation,
  Arg,
  Field,
  Ctx,
  InputType,
  ObjectType,
} from "type-graphql";
import argon2 from "argon2";

@InputType()
class UsernamePasswordInput {
  @Field()
  username: string;
  @Field()
  password: string;
}

@ObjectType()
class FieldError {
  @Field()
  field: string;

  @Field()
  message: string;
}

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];

  @Field(() => User, { nullable: true })
  user?: User;
}

@Resolver()
export class UserResolver {
  @Mutation(() => UserResponse)
  async register(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    if (options.username.length <= 2) {
      return {
        errors: [
          {
            message: "username length should be greater then 2 symbols",
            field: "username",
          },
        ],
      };
    }

    if (options.password.length <= 3) {
        return {
          errors: [
            {
              message: "password length should  be greater then 3 symbols",
              field: "password",
            },
          ],
        };
      }

    const hashedPassword = await argon2.hash(options.password);
    const user = em.create(User, {
      username: options.username,
      password: hashedPassword,
    });

    try {
        await em.persistAndFlush(user);
    } catch(error) {
        if(error.code === '23505' ) {

            return {
                errors: [
                    {message: "user already exist", field: 'username'}
                ]
            }
        }

        return {
            errors: [
                {message: 'unknown error', field: 'username'}
            ]
        }

        console.warn('messag', error.message)
    }


    return { user };
  }

  @Mutation(() => UserResponse)
  async login(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    const user = await em.findOne(User, {
      username: options.username,
    });

    if (!user) {
      return {
        errors: [
          { field: "username", message: "theat username doesn't exits" },
        ],
      };
    }

    const valid = await argon2.verify(user.password, options.password);

    if (!valid) {
      return {
        errors: [
          {
            field: "password",
            message: "inccorrect password",
          },
        ],
      };
    }

    return {
      user,
    };
  }
}
