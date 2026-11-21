import { AgentCoreApplication, type AgentCoreApplicationProps } from '@aws/agentcore-cdk';
import { Stack, type StackProps } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface AgentCoreStackProps extends StackProps {
  /** Props for the AgentCore application, produced by transformAgentCoreJson from agentcore/agentcore.json. */
  application: AgentCoreApplicationProps;
}

/**
 * The stack the AgentCore CLI deploys. Everything declared in agentcore/agentcore.json is
 * created by the AgentCoreApplication construct. Add your own resources below it and wire
 * them to your runtimes and harnesses through the application's accessors.
 */
export class AgentCoreStack extends Stack {
  public readonly application: AgentCoreApplication;

  constructor(scope: Construct, id: string, props: AgentCoreStackProps) {
    super(scope, id, props);
    this.application = new AgentCoreApplication(this, 'Application', props.application);

    // EC2 Doctor: read-only diagnostics, allowed in Mumbai only.
    // runtimes.get() + "?." (instead of runtime('agent')) keeps `agentcore remove all`
    // + `agentcore deploy` working at cleanup time, when the runtime no longer exists.
    this.application.runtimes.get('agent')?.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'Ec2DoctorReadOnlyMumbai',
        actions: [
          'ec2:DescribeInstances',
          'ec2:DescribeInstanceStatus',
          'ec2:DescribeSecurityGroups',
          'ec2:DescribeVolumes',
          'cloudwatch:GetMetricData',
          'ssm:DescribeInstanceInformation',
        ],
        resources: ['*'],
        conditions: { StringEquals: { 'aws:RequestedRegion': 'ap-south-1' } },
      }),
    );
  }
}
