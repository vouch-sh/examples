FROM ruby:4.0-slim

RUN apt-get update -qq && apt-get install -y build-essential libpq-dev libyaml-dev nodejs && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Gemfile Gemfile.lock ./
RUN bundle config set --local frozen true && bundle install

COPY . .

EXPOSE 3000
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0"]
