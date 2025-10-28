# Devolutions Gateway Standalone Web Application
## Adding Protocols and Form Controls to Angular Web Forms: A Developer's Cookbook

## Table of Contents

1. [Introduction](#introduction) 
    - [Overview](#overview)
    - [Prerequisites](#prerequisites)
2. [Web Forms Architecture Overview](#web-forms-architecture-overview)
   - [Project Structure](#project-structure)
   - [Web Client Form Components](#web-client-form-components)
   - [Protocol Enum](#protocol-enum)
3. [Recipe: Adding a New Protocol to the Web Application](#recipe-adding-a-new-protocol-to-the-web-application)
   - [Step 1: Extend the Protocol Enum](#step-1-extend-the-protocol-enum)
   - [Step 2: Create the New Protocol Form Component](#step-2-create-the-new-protocol-form-component)
   - [Step 3: Integrate the New Protocol Form Component into the Main Form Component](#step-3-integrate-the-new-protocol-form-component-into-the-main-form-component)
   - [Step 4: Create a New Protocol Component](#step-4-create-a-new-protocol-component)
4. [Reusable Form Controls Components](#reusable-form-controls-components)
   - [Recipe: Adding a New Reusable Form Control Component](#recipe-adding-a-new-reusable-form-control-component)
     - [Step 1: Create the Port Control Component](#step-1-create-the-port-control-component)
     - [Step 2: Integrate the New Component into Protocol Components](#step-2-integrate-the-new-component-into-protocol-components)
     - [Step 3: Pass Data and FormGroup to the New Component](#step-3-pass-data-and-formgroup-to-the-new-component)
     - [Step 4: Validate and Test](#step-4-validate-and-test)
5. [Form Validation and Custom Validators](#form-validation-and-custom-validators)
   - [Recipe: Implementing Custom Validators](#recipe-implementing-custom-validators)

## Introduction
### Overview
This cookbook is tailored for developers working on an Angular application with a focus on dynamic web
forms that adapt based on user-selected protocols and authentication modes.

It outlines the architecture of web forms and provides detailed examples of how to extend these forms by adding new protocol form controls.

### Prerequisites
- Basic understanding of Angular Reactive Forms Module, FormGroup, and FormBuilder.
- Familiarity with TypeScript and Angular Decorators.
- Familiarity with dynamic component service is also recommended.

## Web Forms Architecture Overview

### Project Structure
```
webapp/                              # pnpm workspace root
├── pnpm-workspace.yaml             # Workspace configuration
├── package.json                    # Root package with shared scripts
│
├── packages/                       # Reusable libraries
│   ├── multi-video-player/        # @devolutions/multi-video-player
│   └── shadow-player/              # @devolutions/shadow-player
│
├── apps/                           # Standalone applications
│   ├── gateway-ui/                 # Main Angular admin interface
│   │   └── src/
│   │       └── client/
│   │           └── app/
│   │               └── modules/
│   │                   └── web-client/
│   │                       ├── form/
│   │                       │   ├── web-client-form.component.html  // Main Web Form
│   │                       │   ├── web-client-form.component.scss
│   │                       │   ├── web-client-form.component.ts
│   │                       │   └── form-components/  // Protocol-specific form components
│   │                       │       ├── ard/
│   │                       │       ├── rdp/
│   │                       │       ├── ssh/
│   │                       │       └── vnc/
│   │                       └── form-controls/  // Reusable form controls
│   └── recording-player/           # Recording player application
│
├── tools/                          # Development tools
│   └── recording-player-tester/
│
└── dist/                           # Centralized build outputs
    ├── gateway-ui/
    └── recording-player/
```

### Web Client Form Components
The main form component, WebClientFormComponent, orchestrates the dynamic loading of protocol-specific forms based on the user's selection. 
It utilizes Angular Reactive Forms to manage form state and validation dynamically.

### Protocol Enum
The Protocol enum facilitates the dynamic loading of form components based on the protocol selected by the user. 
It's extendable to support new protocols as needed.

## Recipe: Adding a New Protocol to the Web Application

### Step 1: Extend the Protocol Enum
Add your new protocol to the `Protocol` enum in the `web-client-protocol.enum.ts`. This example demonstrates adding a new protocol called `XYZ`.

This ensures the new protocol option is available for selection in the protocolOptions array within the WebClientFormComponent. 
You can also add the appropriate tooltip for the new `XYZ` protocol.

````typescript
enum Protocol {
  RDP = 'RDP',
  VNC = 'VNC',
  // Existing protocols
  NEW_PROTOCOL = 'XYZ' // New protocol
}

enum Tooltips {
  'Remote Desktop Protocol' = 'RDP',
  'Teletype Network' = 'Telnet',
  'Secure Shell' = 'SSH',
  'Virtual Network Computing' = 'VNC',
  'Apple Remote Desktop' = 'ARD',
  // Existing protocols
  'XYZ Tooltip' = 'XYZ' // New protocol
}
````

### Step 2: Create the New Protocol Form Component
Generate a new component for the XYZ protocol. This component should include the HTML, SCSS, and TypeScript files necessary for the form. 
For consistency, follow the naming convention and structure used by existing protocols 
(e.g., `xyz-form.component.ts`, `xyz-form.component.html`, `xyz-form.component.scss`).

XYZ Protocol Component (Example)

`xyz-form.component.html`

```angular17html
<div [formGroup]="form">
  <!-- Add your form controls here, similar to other protocol forms -->
</div>
```

`xyz-form.component.ts`

```typescript
@Component({
  selector: 'xyz-form',
  templateUrl: 'xyz-form.component.html',
  styleUrls: ['xyz-form.component.scss']
  })
export class XyzFormComponent implements OnInit {
    @Input() form: FormGroup;
    @Input() inputFormData: any;

    // Initialize and add custom logic for XYZ protocol form
    ngOnInit(): void {
        console.log('XYZ form initialized', this.form);
    }
}
```

### Step 3: Integrate the New Protocol Form Component into the Main Form Component
Modify the 'WebClientFormComponent' to include the new protocol component dynamically based on the protocol selection.

1. Import the `XyzFormComponent` into `web-client-form.component.ts`.
2. Update the template (`web-client-form.component.html`) to conditionally display the XYZ form component:

```angular17html
<!-- Add this inside the <form> tag where other protocol forms are conditionally included -->
<xyz-form *ngIf="isSelectedProtocolXyz()"
          [form]="connectSessionForm"
          [inputFormData]="inputFormData"></xyz-form>
```
*Note: **[inputFormData]="inputFormData"** is form data that is returned to the form if it has previously been processed and returned.
An example would be when a user input an incorrect password. The form data would be returned to the form, with an error message.*

3. Implement the `isSelectedProtocolXyz()` method in `web-client-form.component.ts` to determine when the XYZ protocol is selected.

```typescript
isSelectedProtocolXyz(): boolean {
    return this.getSelectedProtocol() === Protocol.NEW_PROTOCOL; // Use the enum value for XYZ
}
```

### Step 4: Create a New Protocol Component
This step focuses on integrating the new protocol with the Web Session Management System. Continuing with the hypothetical XYZ 
protocol as an example.

##### Step 1: Define the XYZ Protocol Component
###### 1.1 Create Component Files
Generate the '**WebClientXyzComponent**':

- '**web-client-xyz.component.html**'
- '**web-client-xyz.component.scss**'
- '**web-client-xyz.component.ts**'

###### 1.2 Implement the Component
Structure your '**WebClientXyzComponent**' similarly to the existing protocol components like '**WebClientRdpComponent**'. 
Ensure it includes inputs for session data and outputs for session status.

'**web-client-xyz.component.ts:**'

````typescript
@Component({
  selector: 'web-client-xyz',
  templateUrl: 'web-client-xyz.component.html',
  styleUrls: ['web-client-xyz.component.scss']
})
export class WebClientXyzComponent extends WebClientBaseComponent implements OnInit, OnDestroy {
  @Input() webSessionId: string;
  @Output() componentStatus: EventEmitter<ComponentStatus> = new EventEmitter<ComponentStatus>();

  // Define additional properties and methods as required for the XYZ protocol

  ngOnInit(): void {
    // Initialization logic here
  }

  ngOnDestroy(): void {
    // Cleanup logic here
  }

  // Implement protocol-specific connection logic
}
````

##### Step 2: Update WebSessionService
###### 2.1 Register the New Component
Include the '**WebClientXyzComponent**' in the protocolComponentMap and protocolIconMap within the WebSessionService. 
This enables the application to dynamically associate the '**XYZ**' protocol with your new component.

'**web-session.service.ts:**'

````typescript
private protocolComponentMap = {
  [Protocol.RDP]: WebClientRdpComponent,
  // other protocols...
  [Protocol.XYZ]: WebClientXyzComponent, // Add this line
};

private protocolIconMap = {
  [Protocol.RDP]: WebClientRdpComponent.DVL_RDP_ICON,
  // other protocols...
  [Protocol.XYZ]: WebClientXyzComponent.DVL_XYZ_ICON, // Define a constant for the XYZ icon
};
````

##### Step 4: Testing and Validation
###### 4.1 Test the New Component
Ensure '**the WebClientXyzComponent**':

- Renders correctly within the dynamic web forms framework.
- Successfully initiates a session based on the user-provided data.
- Properly cleans up resources on destruction.

###### 4.2 Validate Integration with WebSessionService
Verify that sessions using the '**XYZ**' protocol are correctly created, managed, and terminated within the WebSessionService. 

This includes testing session creation, updates, icon management, and session removal.

## Reusable Form Controls Components

To maintain a modular and reusable structure in your Angular dynamic web forms, it's a best practice to encapsulate form 
controls into their own components. This approach not only enhances reusability across different parts of your application 
but also keeps the codebase clean and maintainable.

### Recipe: Adding a New Reusable Form Control Component
This section guides you through adding a new form control to an existing protocol component within the dynamic web forms architecture.

**Example Scenario**

Let's say we want to add a new reusable form control to the **RDP** protocol component to capture a custom port number. 
We currently capture port as part of the hostname, but it makes for a good example scenario in this document!

##### Step 1: Create the Port Control Component

###### 1.1 Generate Component Files
Create a new Angular component named port-control. This component will include the necessary HTML, TypeScript, and SCSS files:

- **'port-control.component.html'**
- **'port-control.component.ts'**
- **'port-control.component.scss'**

###### 1.2 Implement the Component
Define the structure and behavior of your port control in these files.

**port-control.component.html:**

````angular17html
<div [formGroup]="parentForm">
  <label for="port">Port</label>
  <div class="gateway-form-input">
    <input pInputText id="port" type="number" placeholder="Enter port"
           formControlName="port" required/>
  </div>
  <div class="form-helper-text"
       *ngIf="parentForm.get('port').hasError('required') && parentForm.get('port').touched">
    Port is required.
  </div>
</div>

````

**port-control.component.ts:**

````typescript
@Component({
  selector: 'web-client-port-control',
  templateUrl: 'port-control.component.html',
  styleUrls: ['port-control.component.scss']
})
export class PortControlComponent implements OnInit {

  @Input() parentForm: FormGroup;
  @Input() inputFormData: any;

  ngOnInit(): void {
    this.addControlToParentForm(this.inputFormData);
  }

  private addControlToParentForm(inputFormData?: any): void {
    if (this.parentForm && !this.parentForm.contains('port')) {
      this.parentForm.addControl('port', new FormControl(inputFormData?.port || '', Validators.required));
    }
  }
}
````
*Note: **[inputFormData]="inputFormData"** is form data that is returned to the form if it has previously been processed and returned.
An example would be when a user input an incorrect password. The form data would be returned to the form, with an error message.*

##### Step 2: Integrate the New Component into Protocol Components

###### 2.1 Modify the Protocol Form Templates
In each protocol component where you wish to include the **'port control'**, add the port-control component to the form template. 
For example, in the RDP form component:

**rdp-form.component.html:**

````angular17html
<div [formGroup]="form">
  <!-- Existing form controls -->
  <web-client-port-control [parentForm]="form"
                           [inputFormData]="inputFormData"></web-client-port-control>
  <!-- More form controls -->
</div>
````

##### Step 3: Pass Data and FormGroup to the New Component
Ensure the parent protocol component passes the necessary FormGroup and any initial data to the port-control component through 
the parentForm and inputFormData inputs.


## Form Validation and Custom Validators

### Recipe: Implementing Custom Validators

Define custom validation functions to handle complex validation scenarios, such as validating URL protocols.

See example in the `web-client-kdc-url-control` in the `web-client-kdc-url-control.ts` file.

```typescript
this.formService.addControlToForm(this.parentForm, 'kdcUrl', this.inputFormData,false, false, '', this.kdcServerUrlValidator());


kdcServerUrlValidator(): ValidatorFn {
  return (control: AbstractControl): { [key: string]: any } | null => {
    const validTcpProtocol: boolean = /^(tcp|udp):\/\/.*$/.test(control.value);
    return validTcpProtocol ? null : { 'invalidKdcProtocol': { value: control.value } };
  };
}
```

#### Step 4: Validate and Test
- **Validation**: Confirm the port control correctly validates input, ensuring users can only submit valid port numbers.
- **Functionality**: Test the integration of the new port control within each protocol component, ensuring it behaves as expected across different use cases.
- **Reusability**: Verify that the port control component can be seamlessly reused across various protocol components without code duplication.
