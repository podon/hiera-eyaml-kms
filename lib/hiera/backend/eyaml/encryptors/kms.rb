require 'openssl'
require 'hiera/backend/eyaml/encryptor'
require 'hiera/backend/eyaml/utils'
require 'hiera/backend/eyaml/options'
require 'aws-sdk'

class Hiera
  module Backend
    module Eyaml
      module Encryptors

        class Kms < Encryptor

          self.options = {
            :key_id => {      :desc => "KMS Key ID",
                              :type => :string,
                              :default => "" },
			:sts_role => {
							  :desc => "AWS IAM Role",
							  :type => :string,
							  :default => "" },
            :aws_region => {  :desc => "AWS Region",
                              :type => :string,
                              :default => "ap-southeast-2" }
          }

          VERSION = "0.2"
          self.tag = "KMS"

          def self.encrypt plaintext
			sts_role = self.option :sts_role
            aws_region = self.option :aws_region
            key_id = self.option :key_id
            raise StandardError, "key_id is not defined" unless key_id

			role_cred = Aws::AssumeRoleCredentials.new(
				client: Aws::STS::Client.new(
				  region: aws_region),
				role_arn: sts_role,
				role_session_name: "puppet-hiera-eyaml-decrypt"
			)

            @kms = ::Aws::KMS::Client.new(
              region: aws_region,
			  credentials: role_cred
            )

            resp = @kms.encrypt({
              key_id: key_id,
              plaintext: plaintext
            })

            resp.ciphertext_blob
          end

          def self.decrypt ciphertext
            aws_region = self.option :aws_region
			sts_role = self.option :sts_role

			role_cred = Aws::AssumeRoleCredentials.new(
				client: Aws::STS::Client.new(
				  region: aws_region),
				role_arn: sts_role,
				role_session_name: "puppet-hiera-eyaml-decrypt"
			)

            @kms = ::Aws::KMS::Client.new(
			  credentials: role_cred,
              region: aws_region
            )

            resp = @kms.decrypt({
              ciphertext_blob: ciphertext
            })

            resp.plaintext
          end

        end

      end

    end

  end

end
