import { Alert, AlertType } from "@/components/alert";
import { Button, ButtonVariants } from "@/components/button";
import { Translated } from "@/components/translated";
import { SecondFactorStep } from "@/lib/azdigi/second-factor-step";
import Link from "next/link";

/**
 * AZDIGI: shown by an enrolment page that the server refused because a configured second factor must be verified
 * first. Says why and offers the one way forward (lib/azdigi/second-factor-step.ts); without a step only the reason.
 */
export function SecondFactorFirst({ step }: { step: SecondFactorStep | undefined }) {
  if (!step) {
    return (
      <div className="py-4">
        <Alert>
          <Translated i18nKey="secondFactorRequired" namespace="error" />
        </Alert>
      </div>
    );
  }
  return (
    <div className="py-4" data-testid="second-factor-first">
      <Alert type={AlertType.INFO}>
        <Translated i18nKey={`${step.kind}.description`} namespace="azdigiEnrol" />
      </Alert>
      <div className="mt-8 flex w-full flex-row items-center">
        <span className="flex-grow"></span>
        <Link href={step.href} data-testid="second-factor-first-button">
          <Button type="button" variant={ButtonVariants.Primary}>
            <Translated i18nKey={`${step.kind}.button`} namespace="azdigiEnrol" />
          </Button>
        </Link>
      </div>
    </div>
  );
}
